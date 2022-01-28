"""
Copyright (c) 2020 VMware, Inc.

This product is licensed to you under the Apache License, Version 2.0 (the "License").
You may not use this product except in compliance with the License.

This product may include a number of subcomponents with separate copyright notices
and license terms. Your use of these subcomponents is subject to the terms and
conditions of the subcomponent's license, as noted in the LICENSE file.
"""

import json
import requests
from vra_ipam_utils.ipam import IPAM
from vra_ipam_utils.exceptions import InvalidCertificateException
import logging
from phpipam_client import PhpIpamClient, GET, PATCH

'''
Example payload:

"inputs": {
    "authCredentialsLink": "/core/auth/credentials/13c9cbade08950755898c4b89c4a0",
    "endpointProperties": {
      "hostName": "sampleipam.sof-mbu.eng.vmware.com"
    }
  }
'''
def handler(context, inputs):

    ipam = IPAM(context, inputs)
    IPAM.do_validate_endpoint = do_validate_endpoint

    return ipam.validate_endpoint()

def do_validate_endpoint(self, auth_credentials, cert):
    # Your implemention goes here

    username = auth_credentials["privateKeyId"]
    password = auth_credentials["privateKey"]
    phpIPAMProperties = get_properties(self.inputs)
    appId = phpIPAMProperties["phpIPAM.appId"]
    ipam = PhpIpamClient(
        url=self.inputs["endpointProperties"]["hostName"],
        app_id=appId,
        username=username,
        password=password,
        user_agent='vra-ipam', # custom user-agent header
    )
    try:
        logging.info(ipam.get('/sections/'))
        return {
            "message": "Validated successfully",
            "statusCode": "200"
        }
    except Exception as e:
        logging.error(f"Unexpected exception: {str(e)}")
        """ In case of SSL validation error, a InvalidCertificateException is raised.
            So that the IPAM SDK can go ahead and fetch the server certificate
            and display it to the user for manual acceptance.
        """
        if "SSLCertVerificationError" in str(e) or "CERTIFICATE_VERIFY_FAILED" in str(e) or 'certificate verify failed' in str(e):
            raise InvalidCertificateException("certificate verify failed", self.inputs["endpointProperties"]["hostName"], 443) from e

        raise e

def get_properties(inputs):
    properties_list = inputs["endpointProperties"].get("properties", [])
    properties_list = json.loads(properties_list)
    properties = {}
    for prop in properties_list:
        properties[prop["prop_key"]] = prop["prop_value"]
    return properties