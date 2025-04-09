import json
import sys
import typing

from jinja2 import Template
from time import time

import vyos.opmode
from vyos.utils.convert import seconds_to_human
from vyos.ifconfig import VRRP
from vyos.ifconfig.vrrp import VRRPNoData


VRRP_AUTH_NONE = 0
VRRP_AUTH_PASS = 1
VRRP_AUTH_AH = 2

# https://github.com/acassen/keepalived/blob/59c39afe7410f927c9894a1bafb87e398c6f02be/keepalived/include/vrrp.h#L417
VRRP_STATE_INIT = 0
VRRP_STATE_BACK = 1
VRRP_STATE_MAST = 2
VRRP_STATE_FAULT = 3

VRRP_AUTH_TO_NAME = {
    VRRP_AUTH_NONE: 'NONE',
    VRRP_AUTH_PASS: 'SIMPLE_PASSWORD',
    VRRP_AUTH_AH: 'IPSEC_AH',
}

VRRP_STATE_TO_NAME = {
    VRRP_STATE_INIT: 'INIT',
    VRRP_STATE_BACK: 'BACKUP',
    VRRP_STATE_MAST: 'MASTER',
    VRRP_STATE_FAULT: 'FAULT',
}

def _get_raw_data(group_name: str = None) -> list:
    """
    Retrieve raw JSON data for all VRRP groups.

    Args:
        group_name (str, optional): If provided, filters the data to only
            include the specified vrrp group.

    Returns:
        list: A list of raw JSON data for VRRP groups, filtered by group_name
            if specified.
    """
    try:
        output = VRRP.collect('json')
    except VRRPNoData as e:
        raise vyos.opmode.DataUnavailable(f'{e}')

    data = json.loads(output)

    if not data:
        return []

    if group_name is not None:
        for rec in data:
            if rec['data'].get('iname') == group_name:
                return [rec]
        return []
    return data

def _process_field(data: dict, field: str, true_value: str, false_value: str):
    """
    Updates the given field in the data dictionary with a specified value based
        on its truthiness.

    Args:
        data (dict): The dictionary containing the field to be processed.
        field (str): The key representing the field in the dictionary.
        true_value (str): The value to set if the field's value is truthy.
        false_value (str): The value to set if the field's value is falsy.

    Returns:
        None: The function modifies the dictionary in place.
    """
    data[field] = true_value if data.get(field) else false_value

def _get_formatted_detail_output_as_dict(data: list) -> dict:
    """
    Prepare formatted detail information as a dictionary with keys matching the template fields.
    
    Args:
        data (list): A list of dictionaries containing vrrp group information and statistics.
        
    Returns:
        dict: Dictionary with the same structure as the template display.
    """
    # First process data the same way as in _get_formatted_detail_output
    instances = []
    for instance in data:
        instance_data = {}
        raw_data = instance['data']
        
        # Process state names and boolean fields
        raw_data['state'] = VRRP_STATE_TO_NAME.get(
            raw_data.get('state'), 'unknown'
        )
        raw_data['wantstate'] = VRRP_STATE_TO_NAME.get(
            raw_data.get('wantstate'), 'unknown'
        )
        raw_data['auth_type'] = VRRP_AUTH_TO_NAME.get(
            raw_data.get('auth_type'), 'unknown'
        )
        
        # Process boolean fields
        _process_field(raw_data, 'lower_prio_no_advert', 'false', 'true')
        _process_field(raw_data, 'higher_prio_send_advert', 'true', 'false')
        _process_field(raw_data, 'accept', 'Enabled', 'Disabled')
        _process_field(raw_data, 'notify_deleted', 'Deleted', 'Fault')
        _process_field(raw_data, 'smtp_alert', 'yes', 'no')
        _process_field(raw_data, 'nopreempt', 'Disabled', 'Enabled')
        _process_field(raw_data, 'promote_secondaries', 'Enabled', 'Disabled')
        raw_data['vips'] = raw_data.get('vips', [])
        raw_data['evips'] = raw_data.get('evips', [])
        raw_data['vroutes'] = raw_data.get('vroutes', [])
        raw_data['vrules'] = raw_data.get('vrules', [])
        
        # Now build the structured dictionary with keys matching template fields
        instance_data['VRRP Instance'] = raw_data['iname']
        instance_data['VRRP Version'] = raw_data['version']
        instance_data['State'] = raw_data['state']
        
        if raw_data['state'] == 'BACKUP':
            instance_data['Master priority'] = raw_data['master_priority']
            if raw_data['version'] == 3:
                instance_data['Master advert interval'] = raw_data['master_adver_int']
        
        instance_data['Wantstate'] = raw_data['wantstate']
        instance_data['Last transition'] = raw_data['last_transition']
        instance_data['Interface'] = raw_data['ifp_ifname']
        
        if raw_data.get('dont_track_primary', 0) > 0:
            instance_data['VRRP interface tracking'] = 'disabled'
            
        if raw_data.get('skip_check_adv_addr', 0) > 0:
            instance_data['Skip checking advert IP addresses'] = True
            
        if raw_data.get('strict_mode', 0) > 0:
            instance_data['Enforcing strict VRRP compliance'] = True
        
        instance_data['Gratuitous ARP delay'] = raw_data['garp_delay']
        instance_data['Gratuitous ARP repeat'] = raw_data['garp_rep']
        instance_data['Gratuitous ARP refresh'] = raw_data['garp_refresh']
        instance_data['Gratuitous ARP refresh repeat'] = raw_data['garp_refresh_rep']
        instance_data['Gratuitous ARP lower priority delay'] = raw_data['garp_lower_prio_delay']
        instance_data['Gratuitous ARP lower priority repeat'] = raw_data['garp_lower_prio_rep']
        instance_data['Send advert after receive lower priority advert'] = raw_data['lower_prio_no_advert']
        instance_data['Send advert after receive higher priority advert'] = raw_data['higher_prio_send_advert']
        instance_data['Virtual Router ID'] = raw_data['vrid']
        instance_data['Priority'] = raw_data['base_priority']
        instance_data['Effective priority'] = raw_data['effective_priority']
        instance_data['Advert interval'] = f"{raw_data['adver_int']} sec"
        instance_data['Accept'] = raw_data['accept']
        instance_data['Preempt'] = raw_data['nopreempt']
        
        if raw_data.get('preempt_delay'):
            instance_data['Preempt delay'] = raw_data['preempt_delay']
            
        instance_data['Promote secondaries'] = raw_data['promote_secondaries']
        instance_data['Authentication type'] = raw_data['auth_type']
        
        if raw_data['vips']:
            instance_data['Virtual IP'] = {
                'count': len(raw_data['vips']),
                'addresses': raw_data['vips']
            }
            
        if raw_data['evips']:
            instance_data['Virtual IP Excluded'] = raw_data['evips']
            
        if raw_data['vroutes']:
            instance_data['Virtual Routes'] = raw_data['vroutes']
            
        if raw_data['vrules']:
            instance_data['Virtual Rules'] = raw_data['vrules']
            
        if raw_data.get('track_ifp'):
            instance_data['Tracked interfaces'] = raw_data['track_ifp']
            
        if raw_data.get('track_script'):
            instance_data['Tracked scripts'] = raw_data['track_script']
            
        instance_data['Using smtp notification'] = raw_data['smtp_alert']
        instance_data['Notify deleted'] = raw_data['notify_deleted']
        
        instances.append(instance_data)
    
    return instances
def get_formatted_summary_output(data):
        headers = ['Name', 'Interface', 'VRID', 'State', 'Priority', 'Last Transition']
        results = []

        data = json.loads(data) if isinstance(data, str) else data
        for group in data:
            data = group['data']
            instance = {}

            instance["Name"] = data['iname']
            instance["Interface"] = data['ifp_ifname']
            instance["VRID"] = data['vrid']
            instance["State"] = VRRP_STATE_TO_NAME.get(
            data["state"], 'unknown'
        )
            instance["Priority"] = data['effective_priority']

            since = int(time() - float(data['last_transition']))
            instance["Last Transition"] = seconds_to_human(since)

            results.append(instance)

        # add to the active list disabled instances

        return results
def show_detail(
    raw: bool, group_name: typing.Optional[str] = None
) -> typing.Union[list, str]:
    """
    Display detailed information about the VRRP group.

    Args:
        raw (bool): If True, return raw data instead of formatted output.
        group_name (str, optional): Filter the data by a specific group name,
            if provided.

    Returns:
        list or str: Raw data if `raw` is True, otherwise a formatted detail
            output.
    """
    data = _get_raw_data(group_name)

    if raw:
        return _get_formatted_detail_output_as_dict(data)

    else:
        print("This function is intended for GraphQL Usage only. VRRP group details are not available in this version.")
        return []


def show_statistics(
    raw: bool, group_name: typing.Optional[str] = None
) -> typing.Union[list, str]:
    """
    Display VRRP group statistics.

    Args:
        raw (bool): If True, return raw data instead of formatted output.
        group_name (str, optional): Filter the data by a specific group name,
            if provided.

    Returns:
        list or str: Raw data if `raw` is True, otherwise a formatted statistic
            output.
    """
    data = _get_raw_data(group_name)

    if raw:
        return data

    else:
        print("This function is intended for GraphQL Usage only. VRRP group statistics are not available in this version.")
        return []


def show_summary(raw: bool) -> typing.Union[list, str]:
    """
    Display a summary of VRRP group.

    Args:
        raw (bool): If True, return raw data instead of formatted output.

    Returns:
        list or str: Raw data if `raw` is True, otherwise a formatted summary output.
    """
    data = _get_raw_data()

    if raw:
        return get_formatted_summary_output(data)

    else:
        print("This function is intended for GraphQL Usage only. VRRP group summary is not available in this version.")
        return []