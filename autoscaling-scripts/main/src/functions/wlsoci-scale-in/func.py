#
# Copyright (c) 2023 Oracle, Inc.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl.
#
# Oracle Function script to shutdown OCI instances that running and are identified by a predefined free form tag.
# The tagged VMs are shutdown descending order of their index in their names. So the instance with highest index is shutdown first.
#
# The script requires these configuration variables set:
#  stack_freeform_tag -  The name of VM tag
#  stack_freeform_tag_value - The value of VM tag
#  scaling_size - Number of instances that need to scaled in for each invocation, default "1"
#  load_balancer_id - The ocid of the loadbalancer associated with the vm instances
#  lb_backend_set_name - Name of the backend set for the load balancer that has the backend for the vm instance.
#  wlsc_email_notification_topic_id - OCID of notification topic to send email, optional
#  min_wls_node_count - Scale in stop limit, default is 1
#

import io
import json
import logging
from datetime import datetime

import oci
from fdk import response

logging.basicConfig()
logger = logging.getLogger()

# replace this custom script if needed
stop_command = "sudo su - oracle -c 'sh /opt/scripts/start_stop_mservers.sh {0} stop'"


def handler(ctx, data: io.BytesIO = None):
    cfg = ctx.Config()
    alarm_payload = None
    try:
        alarm_payload = json.loads(data.getvalue().decode('UTF-8')) if data is not None and data.getvalue().decode(
            'UTF-8') != '' else None
    except:
        logger.exception('Payload to function is not a valid JSON: [{0}]'.format(data.getvalue()))

    signer = oci.auth.signers.get_resource_principals_signer()
    resp = scale_in(signer, cfg, alarm_payload)
    return response.Response(
        ctx,
        response_data=json.dumps(resp),
        headers={"Content-Type": "application/json"}
    )


def check_admin_instance(signer, admin_instance, notification_topic_id, alarm_payload, all_running_nodes,
                         scale_in_count):
    if not admin_instance.lifecycle_state in 'RUNNING ':
        error_msg = "Admin Instance {0} is in {0} state. Start the WebLogic admin server to resume autoscaling.".format(
            admin_instance.lifecycle_state, admin_instance.id)
        if notification_topic_id is not None:
            email_body = email_message(alarm_payload, all_running_nodes, (all_running_nodes - scale_in_count),
                                       status_message=error_msg)
            send_email(signer, notification_topic_id, email_body=email_body,
                       subject="Failed to scale in stack from {0} to {1} nodes".format(all_running_nodes, (
                               all_running_nodes - scale_in_count)))

        logger.error(error_msg)
        resp = {"status ": error_msg}
        return resp


def scale_in(signer, cfg, alarm_payload):
    client = oci.core.ComputeClient(config={}, signer=signer)
    try:

        logger.info("Looking up instances in compartment [{0}]".format(signer.compartment_id))

        inst = client.list_instances(signer.compartment_id, sort_by="TIMECREATED", sort_order="DESC")
        running_instances, admin_instance = get_running_instances(inst.data, get_cfg_value(cfg, "stack_freeform_tag"),
                                                                  get_cfg_value(cfg, "stack_freeform_tag_value"))

        notification_topic_id = get_cfg_value(cfg, "wlsc_email_notification_topic_id", default=None)
        total_running_nodes = len(running_instances)
        scale_in_count = int(get_cfg_value(cfg, "min_wls_node_count", "1"))
        all_running_nodes = (total_running_nodes + 1)

        logger.info("INFO: Found [{0}] instances that are running".format(total_running_nodes))
        instances = []
        if total_running_nodes > 0:
            min_node_count = int(get_cfg_value(cfg, "min_wls_node_count", "1"))
            loadbalancer_id = get_cfg_value(cfg, "load_balancer_id", default=None)
            backend_set_name = get_cfg_value(cfg, "lb_backend_set_name", default=None)
            scaling_limit = get_avail_node_count(total_running_nodes, min_node_count, scale_in_count)
            count = 0
            for wlsoci_inst in running_instances:
                if count < scaling_limit:
                    check_admin_instance(signer, admin_instance, notification_topic_id, alarm_payload,
                                         all_running_nodes, scale_in_count)
                    # graceful shutdown
                    node_index = wlsoci_inst.display_name[-1]
                    gracefully_shutdown(signer, admin_instance.id, node_index)
                    set_lb_backend_offline(signer, wlsoci_inst.id, loadbalancer_id, backend_set_name)
                    inst_status = instance_stop(client, wlsoci_inst.id)
                    inst_state = {wlsoci_inst.display_name: {'Id': wlsoci_inst.id, 'status': inst_status}}
                    instances.append(inst_state)
                    delete_lb_backend(cfg, wlsoci_inst.id, signer, loadbalancer_id, backend_set_name)
                    count = count + 1
                else:
                    logger.info("INFO: Scaled in {0} nodes. ".format(scaling_limit))
                    break

            scaled_in_nodes = (all_running_nodes - count)
            if all_running_nodes != scaled_in_nodes:
                message = "Successfully scaled in from {0} to {1} nodes".format(all_running_nodes, scaled_in_nodes)
                if notification_topic_id is not None:
                    email_body = email_message(alarm_payload, all_running_nodes, scaled_in_nodes,
                                               status_message=message)
                    send_email(signer, notification_topic_id, email_body=email_body,
                               subject="Successfully scaled in stack from {0} to {1} nodes".format(all_running_nodes,
                                                                                                   scaled_in_nodes))
            else:
                logger.info("Minimum node count[{0}] has reached. Skipping scale in operation.".format(scaling_limit))

        else:
            logger.info("Scale in not attempted as no running instances were available for scale in")
    except Exception as ex:
        logger.exception("ERROR: accessing Compute instances failed: {0}".format(ex))
        raise
    resp = {"instances": instances}
    return resp


def get_avail_node_count(total_running_nodes, min_node_count, scale_in_count):
    # add 1 for admin server
    available_nodes = total_running_nodes - min_node_count + 1
    if available_nodes < scale_in_count:
        scaling_count = available_nodes
    else:
        scaling_count = scale_in_count
    return scaling_count


def get_running_instances(instances, tagName, tagValue):
    filtered = {}
    logger.info("INFO: Tags filter[ {0}: {1} ]".format(tagName, tagValue))
    admin_instance = None
    if tagName is None or tagValue is None:
        logger.info("ERROR: tagName is not set")
    elif tagValue is None:
        logger.info("ERROR: tagValue is not set")
    else:

        for inst in instances:
            if '-wls-' in inst.display_name:
                index = inst.display_name[-1]
                if int(index) > 0:
                    instance_tags = inst.freeform_tags
                    for tag in instance_tags.keys():
                        if tag.lower() == tagName.lower() and instance_tags[
                            tag].lower() == tagValue.lower() and inst.lifecycle_state in 'RUNNING ':
                            filtered[index] = inst
                elif int(index) == 0:
                    instance_tags = inst.freeform_tags
                    for tag in instance_tags.keys():
                        if tag.lower() == tagName.lower() and instance_tags[
                            tag].lower() == tagValue.lower():
                            admin_instance = inst
    sorted_list = []
    if len(filtered) > 0:
        for k in sorted(filtered.keys(), reverse=True):
            sorted_list.append(filtered[k])
    return sorted_list, admin_instance


def gracefully_shutdown(signer, admin_instance_id, wls_node_index):
    try:
        logger.info("Running graceful shutdown on Admin Node: {0}".format(admin_instance_id))
        command_text = stop_command.format(wls_node_index)
        logger.info("Executing command [{0}] on admin instance for updating the domain config for scale in".format(
            command_text))
        resp = execute_command(signer, command_text, admin_instance_id, "Scale-in run command", 240)
        logger.info("Scale-in command execution response: {0}".format(str(resp.content)))
    except Exception as ex:
        logger.exception('Failed to stop the servers gracefully {0}'.format(ex))


def execute_command(signer, commandText, targetInstanceOCID, commandDispName, execution_time_out_in_seconds):
    """
    Executes the run command on WebLogic admin instance.
    :param signer:
    :param commandText:
    :param targetInstanceOCID:
    :param commandDispName:
    :param execution_time_out_in_seconds:
    :return:
    """
    client = oci.compute_instance_agent.ComputeInstanceAgentClient(config={}, signer=signer)
    resp = ""
    try:
        source = oci.compute_instance_agent.models.InstanceAgentCommandSourceViaTextDetails(source_type='TEXT',
                                                                                            text=str(commandText))
        output = oci.compute_instance_agent.models.InstanceAgentCommandOutputViaTextDetails(output_type='TEXT')
        content = oci.compute_instance_agent.models.InstanceAgentCommandContent(output=output, source=source)
        targetInstance = oci.compute_instance_agent.models.InstanceAgentCommandTarget(instance_id=targetInstanceOCID)
        commandDetails = oci.compute_instance_agent.models.CreateInstanceAgentCommandDetails(
            compartment_id=signer.compartment_id, execution_time_out_in_seconds=execution_time_out_in_seconds,
            target=targetInstance, content=content, display_name=commandDispName)
        resp = client.create_instance_agent_command(create_instance_agent_command_details=commandDetails)
        logger.info('Remote command execution response: {0}'.format(str(resp.data)))
    except Exception as ex:
        logger.exception('Error in execution of command : ' + commandText)
        raise

    return resp.data


def set_lb_backend_offline(signer, instance_id, loadbalancer_id, backend_set_name):
    """
    Updates load balancer backend to offline state for the instance id
    """
    try:
        load_balancer_client = oci.load_balancer.LoadBalancerClient(config={}, signer=signer)
        if loadbalancer_id is not None:
            if backend_set_name is not None:
                response_lb_backend_set = load_balancer_client.list_backends(loadbalancer_id, backend_set_name)
                instance_ip_addresses = get_instance_ip_addresses(instance_id, signer)
                update_lb_backend = None
                backend_name = None
                for backend in response_lb_backend_set.data:
                    if backend.ip_address in instance_ip_addresses:
                        # found the backend
                        update_lb_backend = oci.load_balancer.models.UpdateBackendDetails(weight=backend.weight,
                                                                                          backup=backend.backup,
                                                                                          drain=True,
                                                                                          offline=True)
                        backend_name = backend.name

                        # update backend offline
                        logger.info(
                            "Updating lb backend state for loadbalancer [{0}], backend_set [{1}] and backend [{2}]".format(
                                loadbalancer_id, backend_set_name, backend_name))
                        load_balancer_client_composite = oci.load_balancer.LoadBalancerClientCompositeOperations(
                            load_balancer_client)
                        load_balancer_client_composite.update_backend_and_wait_for_state(update_lb_backend,
                                                                                         loadbalancer_id,
                                                                                         backend_set_name=backend_set_name,
                                                                                         backend_name=backend_name,
                                                                                         wait_for_states=[
                                                                                             oci.load_balancer.models.WorkRequest.LIFECYCLE_STATE_SUCCEEDED])
                        logger.info("Successfully updated lb backend [{0}] state to offline".format(backend_name))
            else:
                logger.error("Missing configuration variable lb_backend_set_name")
        else:
            logger.error("Missing configuration variable load_balancer_id")

    except oci.exceptions.ServiceError as e:
        logger.exception(
            'Updating load balancer [{0}] backend [{1}] failed. {2}'.format(loadbalancer_id, backend_set_name, e))


def delete_lb_backend(cfg, instance_id, signer, loadbalancer_id, backend_set_name):
    """
    Removes the backend for node that is shutdown
    """
    try:
        load_balancer_client = oci.load_balancer.LoadBalancerClient(config={}, signer=signer)
        if loadbalancer_id is not None:
            if backend_set_name is not None:
                response_lb_backend_set = load_balancer_client.list_backends(loadbalancer_id, backend_set_name)
                instance_ip_addresses = get_instance_ip_addresses(instance_id, signer)
                backend_names = []
                for backend in response_lb_backend_set.data:
                    if backend.ip_address in instance_ip_addresses:
                        # found the backend
                        backend_names.append(backend.name)

                # update backend offline
                if len(backend_names) > 0:
                    logger.info(
                        "Deleting lb backends for loadbalancer [{0}], backend_set [{1}] and backend(s) [{2}]".format(
                            loadbalancer_id, backend_set_name, backend_names))
                    load_balancer_client_composite = oci.load_balancer.LoadBalancerClientCompositeOperations(
                        load_balancer_client)

                    for backend_name in backend_names:
                        load_balancer_client_composite.delete_backend_and_wait_for_state(loadbalancer_id,
                                                                                         backend_set_name, backend_name,
                                                                                         wait_for_states=[
                                                                                             oci.load_balancer.models.WorkRequest.LIFECYCLE_STATE_SUCCEEDED])

                    logger.info("Successfully removed the backends from load balancer")
            else:
                logger.info("ERROR: Missing env variable lb_backend_set_name in function configuration ")
        else:
            logger.info("WARNING: Missing env variable load_balancer_id in function configuration ")

    except oci.exceptions.ServiceError as e:
        logger.exception(
            'Deletion of load balancer [{0}] backend [{1}] failed. {2}'.format(loadbalancer_id, backend_set_name, e))


def get_instance_ip_addresses(instance_id, signer):
    """
    Returns the instance ip addresses for the VM instance
    """
    ip_addresses = []
    try:
        compute_client = oci.core.ComputeClient(config={}, signer=signer)
        vnic_attachments = compute_client.list_vnic_attachments(signer.compartment_id, instance_id=instance_id)
        virtual_network_client = oci.core.VirtualNetworkClient(config={}, signer=signer)
        vnics = []

        for va in vnic_attachments.data:
            vn = virtual_network_client.get_vnic(vnic_id=va.vnic_id).data
            vnics.append(vn)

        for vnic in vnics:
            private_ips_for_vnic = virtual_network_client.list_private_ips(vnic_id=vnic.id)

            for private_ip in private_ips_for_vnic.data:
                ip_addresses.append(private_ip.ip_address)
    except oci.exceptions.ServiceError as e:
        logger.exception('Getting private ip addresses for instance [{0}]. Exception[{1}]'.format(instance_id, e))

    return ip_addresses


def instance_stop(compute_client, instance_id):
    logger.info('Stopping Instance: {}'.format(instance_id))
    try:
        instance_status = compute_client.get_instance(instance_id).data.lifecycle_state
        if instance_status in 'RUNNING':
            try:
                compute_client_composite_operations = oci.core.ComputeClientCompositeOperations(compute_client)
                logger.info('INFO: Waiting for STOPPED state for instance_id=[{0}]'.format(instance_id))

                compute_client_composite_operations.instance_action_and_wait_for_state(
                    instance_id=instance_id,
                    action='STOP',
                    wait_for_states=[oci.core.models.Instance.LIFECYCLE_STATE_STOPPED])

            except oci.exceptions.ServiceError as e:
                logger.exception('Stopping instance failed. {0}'.format(e))
                raise
        else:
            logger.warning('The instance was in the incorrect state to stop'.format(instance_id))
            raise
    except oci.exceptions.ServiceError as e:
        logger.exception('Stopping instance failed. {0}'.format(e))
        raise
    logger.info('Stopped Instance: {}'.format(instance_id))

    instance_status = compute_client.get_instance(instance_id).data.lifecycle_state
    return instance_status


def email_message(alarm_payload, initial_node_count, final_node_count, status_message):
    alarm_id = body = title = alarm_body = dedupekey = alarm_timestamp = ""

    if alarm_payload is not None:
        if 'body' in alarm_payload:
            body = alarm_payload["body"]
            logger.info("Body: " + body)

        if "title" in alarm_payload:
            title = alarm_payload["title"]
            logger.info("Title: " + title)

        if "body" in alarm_payload:
            alarm_body = alarm_payload["body"]
            logger.info("Body: " + body)

        if "dedupeKey" in alarm_payload:
            dedupekey = alarm_payload["dedupeKey"]
            logger.info('Dedupe key = ' + dedupekey)

        if "timestampEpochMillis" in alarm_payload:
            time_in_millis = alarm_payload["timestampEpochMillis"] / 1000.0
            alarm_timestamp = datetime.fromtimestamp(time_in_millis).strftime('%Y-%m-%d %H:%M:%S')
            logger.info('Alarm timestamp = ' + alarm_timestamp)

        if "alarmMetaData" in alarm_payload:
            alarmMetadataList = alarm_payload['alarmMetaData']
            if len(alarmMetadataList) > 0:
                alarm_id = alarmMetadataList[0]['id']

    body_msg = """
        Alarm Name: {0}
        Alarm ID: {1}
        Alarm Body: {2}
        Time: {3}
        Scale In Node count  {4} -> {5}
        Status: {6}
        Dedupe Key: {7}
        """.format(title, alarm_id, alarm_body, alarm_timestamp,
                   initial_node_count, final_node_count, status_message, dedupekey)

    return body_msg


def send_email(signer, topic_id, email_body=None, subject=""):
    """
    Sends an email to the email notification topic upon completion of the scaling function.

    :param signer:
    :param topic_id:
    :param email_body:
    :param subject
    :return:
    """
    ons_client = oci.ons.NotificationDataPlaneClient(config={}, signer=signer)
    try:

        message_details = oci.ons.models.MessageDetails(
            body=email_body,
            title=subject)
        publish_message_response = ons_client.publish_message(topic_id, message_details=message_details,
                                                              message_type="RAW_TEXT")
        logger.info(publish_message_response)
    except(Exception, ValueError) as ex:
        logger.exception("ERROR: sending confirmation email failed: {0}".format(ex))


def get_cfg_value(cfg, name, default=None):
    if name in cfg:
        return cfg.get(name)
    return default
