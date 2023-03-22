## Autoscaling Scripts for WebLogic For OCI


Oracle WebLogic for OCI Marketplace offering creates a OCI stack of WebLogic Servers with autoscaling capabilities.
For more details about deploying the OCI Terraform stack for WebLogic Server through the OCI Marketplace, visit the ["Auto-scaling in Oracle WebLogic Server for OCI"](https://blogs.oracle.com/weblogicserver/post/auto-scaling-in-oracle-weblogic-server-for-oci) blog.

The scripts in this projects are only for demonstration of alternative way of autoscaling the WebLogic For OCI stack. If the required number of nodes can be predicted for higher workloads, users can  provision or scale out the stack to the number of nodes required to support the maximum predicted workload. For handling standard workloads, a sufficient number of nodes can be kept running while shutting down the extra nodes needed for high load conditions. 
The OCI scaling functions in this project provide a way to start and stop the servers based on scaling events of WebLogic For OCI autoscaling framework.
The [blog](http://www.addlink.com) covers the steps involved in configuring functions and the start/stop script.