#!/usr/bin/env python
#
# Copyright 2017 Google, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""This application demonstrates how to perform operations on data (content)
when using Google Cloud CDN (Content Delivery Network).

For more information, see the README.md under /cdn and the documentation
at https://cloud.google.com/cdn/docs.
"""

import argparse
import base64
from datetime import datetime
import hashlib
import hmac

from six.moves import urllib

def sign_cookie():
    """Gets the Signed cookie value for the specified URL prefix and configuration.

    Args:
        url_prefix: URL prefix to sign as a string.
        key_name: name of the signing key as a string.
        base64_key: signing key as a base64 encoded string.
        expiration_time: expiration time as a UTC datetime object.

    Returns:
        Returns the Cloud-CDN-Cookie value based on the specified configuration.
    """
    url_prefix = 'http://apess.tk/main.m3u8/'
    key_name = 'onekey'
    base64_key = 'VFB1a0E3YTJycHVfZjE1b0ZteTlLdz09'
    expiration_time = datetime.strptime('25 Nov 2022 15:19:49','%d %b %Y %H:%M:%S')

    encoded_url_prefix = base64.urlsafe_b64encode(
            url_prefix.strip().encode('utf-8')).decode('utf-8')
    epoch = datetime.utcfromtimestamp(0)
    expiration_timestamp = int((expiration_time - epoch).total_seconds())
    decoded_key = base64.urlsafe_b64decode(base64_key)

    policy_pattern = u'URLPrefix={encoded_url_prefix}:Expires={expires}:KeyName={key_name}'
    policy = policy_pattern.format(
            encoded_url_prefix=encoded_url_prefix,
            expires=expiration_timestamp,
            key_name=key_name)

    digest = hmac.new(
            decoded_key, policy.encode('utf-8'), hashlib.sha1).digest()
    signature = base64.urlsafe_b64encode(digest).decode('utf-8')

    signed_policy = u'Cloud-CDN-Cookie={policy}:Signature={signature}'.format(
            policy=policy, signature=signature)
    print(signed_policy)
sign_cookie()
