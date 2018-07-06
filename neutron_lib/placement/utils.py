# Copyright 2018 Ericsson
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import re
import uuid

from oslo_log import log as logging
import six

from neutron_lib._i18n import _
from neutron_lib.placement import constants


LOG = logging.getLogger(__name__)


def traitify(string):
    '''Transliterate a string into the character set of Placement traits.

    Traits must be expressed in a character set from the seventies. When
    assembling custom trait names this function makes strings includable into
    trait names. Beware this is not bijective, collisions may happen.

    cf. https://github.com/openstack/nova/blob/18.0.0.0b2
               /nova/api/openstack/placement/schemas/trait.py#L22
    '''
    return re.sub(r'[^A-Z0-9_]', '_', string.upper())


def physnet_trait(physnet):
    return '%s%s' % (constants.TRAIT_PREFIX_PHYSNET, traitify(physnet))


def vnic_type_trait(vnic_type):
    return '%s%s' % (constants.TRAIT_PREFIX_VNIC_TYPE, traitify(vnic_type))


def six_uuid5(namespace, name):
    '''A uuid.uuid5 variant that takes utf-8 'name' both in Python 2 and 3.

    uuid.uuid5() behaves seemingly consistently but still incompatibly
    different in cPython 2 and 3. Both expects the 'name' parameter to have
    the type of the default string literal in each language version.
    That is:
        The cPython 2 variant expects a byte string.
        The cPython 3 variant expects a unicode string.
    Which types are called respectively 'str' and 'str' for the sake of
    confusion. But the sha1() hash inside uuid5() always needs a byte string,
    so we have to treat the two versions asymmetrically. See also:

    cPython 2.7:
    https://github.com/python/cpython/blob
           /ea9a0994cd0f4bd37799b045c34097eb21662b3d/Lib/uuid.py#L603
    cPython 3.6:
    https://github.com/python/cpython/blob
           /e9e2fd75ccbc6e9a5221cf3525e39e9d042d843f/Lib/uuid.py#L628
    '''
    if six.PY2:
        name = name.encode('utf-8')
    return uuid.uuid5(namespace=namespace, name=name)


# NOTE(bence romsics): The spec said: "Agent resource providers shall
# be identified by their already existing Neutron agent UUIDs [...]"
#
# https://review.openstack.org/#/c/508149/14/specs/rocky
#        /minimum-bandwidth-allocation-placement-api.rst@465
#
# However we forgot that agent UUIDs are not stable through a few
# admin operations like after a manual 'openstack network agent
# delete'. Here we make up a stable UUID instead.
def agent_resource_provider_uuid(namespace, host):
    '''Generate a stable UUID for an agent.

    Based on:
    * a mechanism driver specific namespace (ie. another UUID)
    * the agent's hostname
    '''
    return six_uuid5(namespace=namespace, name=host)


def device_resource_provider_uuid(namespace, host, device, separator=':'):
    '''Generate a stable UUID for a physical network device.

    Based on:
    * a mechanism driver specific namespace (ie. another UUID)
    * the agent's hostname
    * the device's name (that supposed to be unique inside the host)
    '''
    name = '%s%s%s' % (host, separator, device)
    return six_uuid5(namespace=namespace, name=name)


def _parse_bandwidth_value(bw_str):
    '''Parse the config string of a bandwidth value to an integer.

    :returns: The bandwidth value as an integer or None if not set in config.
    :raises: ValueError on invalid input.
    '''
    try:
        if bw_str == '':
            bw = None  # not set in configuration
        else:
            bw = int(bw_str)
            if bw < 0:
                raise ValueError()
    except ValueError:
        raise ValueError(_(
            'Cannot parse resource_provider_bandwidths. '
            'Expected: non-negative integer bandwidth value, got: %s') %
            bw_str)
    return bw


def parse_rp_bandwidths(bandwidths):
    '''Parse and validate config option: resource_provider_bandwidths.

    Input in the config:
        resource_provider_bandwidths = eth0:10000:10000,eth1::10000,eth2::
    Input here:
        ['eth0:10000:10000', 'eth1::10000', 'eth2::']
    Output:
        {
            'eth0': {'egress': 10000, 'ingress': 10000},
            'eth1': {'egress': None, 'ingress': 10000},
            'eth2': {'egress': None, 'ingress': None},
        }
    '''

    rv = {}
    for bandwidth in bandwidths:
        try:
            device, egress_str, ingress_str = bandwidth.split(':')
        except ValueError:
            raise ValueError(_(
                'Cannot parse resource_provider_bandwidths. '
                'Expected: DEVICE:EGRESS:INGRESS, got: %s') % bandwidth)
        if device in rv:
            raise ValueError(_(
                'Cannot parse resource_provider_bandwidths. '
                'Same device listed multiple times: %s') % device)
        egress = _parse_bandwidth_value(egress_str)
        ingress = _parse_bandwidth_value(ingress_str)
        rv[device] = {
            'egress': egress,
            'ingress': ingress,
        }
    return rv


def parse_rp_inventory_defaults(inventory_defaults):
    '''Parse and validate config option: parse_rp_inventory_defaults.

    Cast the dict values to the proper numerical types.

    Input in the config:
        resource_provider_inventory_defaults = allocation_ratio:1.0,min_unit:1
    Input here:
        {
            'allocation_ratio': '1.0',
            'min_unit': '1',
        }
    Output here:
        {
            'allocation_ratio': 1.0,
            'min_unit': 1,
        }
    '''

    unexpected_options = (set(inventory_defaults.keys()) -
                          constants.INVENTORY_OPTIONS)
    if unexpected_options:
        raise ValueError(_(
            'Cannot parse inventory_defaults. Unexpected options: %s') %
            ','.join(unexpected_options))

    # allocation_ratio is a float
    try:
        if 'allocation_ratio' in inventory_defaults:
            inventory_defaults['allocation_ratio'] = float(
                inventory_defaults['allocation_ratio'])
            if inventory_defaults['allocation_ratio'] < 0:
                raise ValueError()
    except ValueError:
        raise ValueError(_(
            'Cannot parse inventory_defaults.allocation_ratio. '
            'Expected: non-negative float, got: %s') %
            inventory_defaults['allocation_ratio'])

    # the others are ints
    for key in ('min_unit', 'max_unit', 'reserved', 'step_size'):
        try:
            if key in inventory_defaults:
                inventory_defaults[key] = int(inventory_defaults[key])
                if inventory_defaults[key] < 0:
                    raise ValueError()
        except ValueError:
            raise ValueError(_(
                'Cannot parse inventory_defaults.%(key)s. '
                'Expected: non-negative int, got: %(got)s') % {
                    'key': key,
                    'got': inventory_defaults[key],
            })

    return inventory_defaults
