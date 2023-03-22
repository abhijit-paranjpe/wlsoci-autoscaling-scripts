#
# Copyright (c) 2023 Oracle, Inc.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl.
#
# Oracle Function script to start  OCI instances that are shutdown and are identified by a predefined free form tag.
# The tag VMs are started in descending order of creation time. So the instance that is first created is started first.
# If load balancer is provisioned it will attempt to set the corresponding backend to ONLINE state to route the traffic to that backend.
#
# The script requires these env variables set:
# The script requires these env variables set:
#  stack_freeform_tag -  The name of VM tag
#  stack_freeform_tag_value - The value of VM tag
#  scaling_size - Number of instances that need to scaled out for each invocation, default "1"
#  load_balancer_id - The ocid of the loadbalancer associated with the vm instances
#  lb_backend_set_name - Name of the backend set for the load balancer that has the backend for the vm instance.
#  wlsc_email_notification_topic_id - OCID of notification topic to send email, optional
#  lb_backend_ports - (optional) defaults to 7003 as created by marketplace stack
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
startup_command = "sudo su - oracle -c 'sh /opt/scripts/start_stop_mservers.sh {0} start'"


def handler(ctx, data: io.BytesIO = None):
    cfg = ctx.Config()
    signer = oci.auth.signers.get_resource_principals_signer()
    alarm_payload = None
    try:
        alarm_payload = json.loads(data.getvalue().decode('UTF-8')) if data is not None and data.getvalue().decode(
            'UTF-8') != '' else None
    except:
        logger.exception('Payload to function is not a valid JSON: [{0}]'.format(data.getvalue()))

    resp = scale_out(signer, cfg, alarm_payload)

    return response.Response(
        ctx,
        response_data=json.dumps(resp),
        headers={"Content-Type": "application/json"}
    )


def check_admin_instance(signer, admin_instance, notification_topic_id, alarm_payload, initial_node_count,
                         scaling_limit):
    if admin_instance.lifecycle_state in 'STOPPED ':
        error_msg = "Admin Instance {0} is in stopped state. Start the WebLogic admin server to resume autoscaling.".format(
            admin_instance.id)

        if notification_topic_id is not None:
            email_body = email_message(alarm_payload, initial_node_count, (initial_node_count + scaling_limit),
                                       status_message=error_msg)
            send_email(signer, notification_topic_id, email_body=email_body,
                       subject="Failed autoscaling stack from {0} to {1} nodes".format(initial_node_count, (
                               initial_node_count + scaling_limit)))

        logger.error(error_msg)
        resp = {"status ": error_msg}
        return resp


def scale_out(signer, cfg, alarm_payload):
    """
    Returns environment value otherwise default value
    """
    # OCI API to manage Compute resources such as compute instances, block storage volumes, etc.
    client = oci.core.ComputeClient(config={}, signer=signer)
    try:
        scaling_limit = int(get_cfg_value(cfg, "scaling_size", "1"))

        # Returns a list of all instances in the current compartment
        logger.info("Looking up instances in compartment [{0}]".format(signer.compartment_id))
        response = client.list_instances(signer.compartment_id, sort_by="TIMECREATED", sort_order="ASC")
        initial_node_count, stopped_instances, admin_instance = get_stopped_instances(response.data, get_cfg_value(cfg,
                                                                                                                   "stack_freeform_tag"),
                                                                                      get_cfg_value(cfg,
                                                                                                    "stack_freeform_tag_value"))
        notification_topic_id = get_cfg_value(cfg, "wlsc_email_notification_topic_id", default=None)

        logger.info("Found [{0}] instances that are stopped ".format(len(stopped_instances)))
        instances = []
        loadbalancer_id = get_cfg_value(cfg, "load_balancer_id", default=None)
        backend_set_name = get_cfg_value(cfg, "lb_backend_set_name", default=None)
        total_stopped_instances = len(stopped_instances)
        server_startup_failed_nodes = []
        if total_stopped_instances > 0:
            count = 0
            for wlsoci_inst in stopped_instances:
                if count < scaling_limit:
                    check_admin_instance(signer, admin_instance, notification_topic_id, alarm_payload,
                                         initial_node_count, scaling_limit)
                    wls_node_index = wlsoci_inst.display_name[-1]
                    inst_status = instance_start(client, wlsoci_inst.id, signer)
                    inst_state = {wlsoci_inst.display_name: {'Id': wlsoci_inst.id, 'status': inst_status}}
                    instances.append(inst_state)
                    # start wls ms server
                    success = start_wls_server(signer, admin_instance.id, wls_node_index)
                    if success:
                        # add server to lb backend
                        add_lb_backend(cfg, wlsoci_inst.id, signer, loadbalancer_id, backend_set_name)
                    else:
                        logger.info("Failed to start server on node[{0}].".format(wlsoci_inst.display_name))
                        server_startup_failed_nodes.append(wlsoci_inst.display_name)

                    count = count + 1
                else:
                    logger.info("Reached scaling limit [{0}]. Cannot scale out further.".format(scaling_limit))
                    break
            if len(server_startup_failed_nodes) > 0:
                status_message = "Successfully started compute nodes {0} nodes. Failed to start the managed server on these nodes -" + str(
                    server_startup_failed_nodes)
            else:
                status_message = "Successfully scaled out {0} nodes."
            scaled_out_node_count = scaling_limit
            if scaling_limit >= total_stopped_instances:
                scaled_out_node_count = total_stopped_instances
                status_message = status_message.format(total_stopped_instances)
            else:
                status_message = status_message.format(scaling_limit)

            logger.info(status_message)

            if notification_topic_id is not None:
                email_body = email_message(alarm_payload, initial_node_count,
                                           (initial_node_count + scaled_out_node_count), status_message=status_message)
                send_email(signer, notification_topic_id, email_body=email_body,
                           subject="Successfully scaled out stack from {0} to {1}".format(initial_node_count, (
                                       initial_node_count + scaled_out_node_count)))
        else:
            logger.info(
                "All compute nodes in the are running. Cannot scale out further until new nodes are provisioned.")
    except Exception as ex:
        error_msg = "Failed to scale out stack due to following exception: {0}".format(str(ex))
        logger.exception(error_msg)
        if notification_topic_id is not None:
            email_body = email_message(alarm_payload, initial_node_count, (initial_node_count + scaling_limit),
                                       status_message=error_msg)
            send_email(signer, notification_topic_id, email_body=email_body,
                       subject="Failed scaling out stack from {0} to {1} nodes".format(initial_node_count, (
                                   initial_node_count + scaled_out_node_count)))

        raise
    resp = {"instances": instances}
    return resp


def get_stopped_instances(instances, tagName, tagValue):
    filtered = {}
    logger.info("INFO: Tags filter[ {0}: {1} ]".format(tagName, tagValue))
    admin_instance = None
    if tagName is None or tagValue is None:
        logger.info("ERROR: tagName is not set")
    elif tagValue is None:
        logger.info("ERROR: tagValue is not set")
    else:
        initial_node_count = 0
        for inst in instances:
            if '-wls-' in inst.display_name:

                index = inst.display_name[-1]
                if int(index) > 0:
                    instance_tags = inst.freeform_tags
                    for tag in instance_tags.keys():
                        if tag.lower() == tagName.lower() and instance_tags[
                            tag].lower() == tagValue.lower():
                            if inst.lifecycle_state in 'STOPPED ':
                                filtered[index] = inst
                            elif inst.lifecycle_state in 'RUNNING':
                                initial_node_count += 1
                elif int(index) == 0:
                    instance_tags = inst.freeform_tags
                    for tag in instance_tags.keys():
                        if tag.lower() == tagName.lower() and instance_tags[tag].lower() == tagValue.lower():
                            admin_instance = inst
                            initial_node_count += 1

    sorted_list = []
    if len(filtered) > 0:
        for k in sorted(filtered.keys()):
            sorted_list.append(filtered[k])
    return initial_node_count, sorted_list, admin_instance


def instance_start(compute_client, instance_id, signer):
    """
    Returns the state of the VM instance Starts VM instance and updates load balancer backend to online state
    """
    logger.info('Starting Instance: {}'.format(instance_id))
    try:
        instance_status = compute_client.get_instance(instance_id).data.lifecycle_state

        if instance_status in 'STOPPED':
            try:
                compute_client_composite_operations = oci.core.ComputeClientCompositeOperations(compute_client)
                logger.info('INFO: Waiting for STARTED state for instance_id=[{0}]'.format(instance_id))

                compute_client_composite_operations.instance_action_and_wait_for_state(
                    instance_id=instance_id,
                    action='START',
                    wait_for_states=[oci.core.models.Instance.LIFECYCLE_STATE_RUNNING])
            except oci.exceptions.ServiceError as e:
                logger.info('Starting instance [{0}] failed. {0}'.format(instance_id, e))
                raise
        else:
            logger.info('The instance was in the incorrect state to start'.format(instance_id))
            raise
    except oci.exceptions.ServiceError as e:
        logger.exception('Starting instance failed. {0}'.format(e))
        raise

    logger.info('Started Instance: {}'.format(instance_id))
    instance_status = compute_client.get_instance(instance_id).data.lifecycle_state
    return instance_status


def start_wls_server(signer, admin_instance_id, wls_node_index):
    try:
        logger.info("Running start managed server on Admin Node: {0}".format(admin_instance_id))
        command_text = startup_command.format(wls_node_index)
        logger.info("Executing command [{0}] on admin instance for starting managed server".format(command_text))

        resp = execute_command(signer, command_text, admin_instance_id, "Scale-out run command", 240)
        logger.info("Scale-out command execution response: {0}".format(str(resp.content)))
        return True
    except Exception as ex:
        logger.exception('Failed to start the servers {0}'.format(ex))
        return False


def execute_command(signer, commandText, targetInstance_id, commandDispName, execution_time_out_in_seconds):
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
        targetInstance = oci.compute_instance_agent.models.InstanceAgentCommandTarget(instance_id=targetInstance_id)
        commandDetails = oci.compute_instance_agent.models.CreateInstanceAgentCommandDetails(
            compartment_id=signer.compartment_id, execution_time_out_in_seconds=execution_time_out_in_seconds,
            target=targetInstance, content=content, display_name=commandDispName)
        resp = client.create_instance_agent_command(create_instance_agent_command_details=commandDetails)
        logger.info('Remote command execution response: {0}'.format(str(resp.data)))
    except Exception as ex:
        logger.exception('Error in execution of command : ' + commandText)
        raise

    return resp.data


def add_lb_backend(cfg, instance_id, signer, loadbalancer_id=None, backend_set_name=None):
    """
    Adds the backend for node that was started
    """
    try:
        load_balancer_client = oci.load_balancer.LoadBalancerClient(config={}, signer=signer)
        if loadbalancer_id is not None:
            if backend_set_name is not None:
                response_lb_backend_set = load_balancer_client.list_backends(loadbalancer_id, backend_set_name)
                instance_ip_addresses = get_instance_ip_addresses(instance_id, signer)
                ports_list = get_cfg_value(cfg, "lb_backend_ports", "7003")
                ports = ports_list.split(',')

                add_backend = True
                existing_backend = None
                for backend in response_lb_backend_set.data:
                    existing_backend = backend
                    if backend.ip_address in instance_ip_addresses and backend.port in ports:
                        # found the backend
                        add_backend = False
                        break

                # add backend offline
                if add_backend:
                    logger.info(
                        "Adding lb backend(s) to backend set for loadbalancer [{0}], backend_set [{1}], ports[%s] ]".format(
                            loadbalancer_id, backend_set_name, ports))
                    load_balancer_client_composite = oci.load_balancer.LoadBalancerClientCompositeOperations(
                        load_balancer_client)
                    for port in ports:
                        backend_details = oci.load_balancer.models.CreateBackendDetails(
                            ip_address=instance_ip_addresses[0],
                            port=int(port), weight=existing_backend.weight,
                            backup=False, drain=False,
                            offline=False)
                        load_balancer_client_composite.create_backend_and_wait_for_state(backend_details,
                                                                                         loadbalancer_id,
                                                                                         backend_set_name,
                                                                                         wait_for_states=[
                                                                                             oci.load_balancer.models.WorkRequest.LIFECYCLE_STATE_SUCCEEDED])

                        logger.info(
                            "Successfully added the backend to backend set [{0}, {1}]".format(backend_set_name, port))
                else:
                    print("Found existing backend [{0},{0},{0}]".format(existing_backend.name, existing_backend.port,
                                                                        existing_backend.offline))
            else:
                logger.info("ERROR: Missing configuration for LB_BACKEND_SET_NAME in function configuration ")
        else:
            logger.info("WARNING: Missing configuration for LOADBALANCER_ID in function configuration ")

    except oci.exceptions.ServiceError as e:
        logger.exception(
            'Deletion of load balancer [{0}] backend [{1}] failed. {2}'.format(loadbalancer_id, backend_set_name, e))


def get_instance_ip_addresses(instance_id, signer):
    """
    Returns the instance private ip addresses for the VM instance
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
        Scale Out Node count  {4} -> {5}
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
