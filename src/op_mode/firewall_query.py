#!/usr/bin/env python3
#
# Copyright (C) 2023-2024 VyOS maintainers and contributors
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 or later as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import json
import re

from vyos.config import Config
from vyos.utils.process import cmd
from vyos.utils.dict import dict_search_args
def get_config_node(conf, node=None, family=None, hook=None, priority=None):
    if node == 'nat':
        if family == 'ipv6':
            config_path = ['nat66']
        else:
            config_path = ['nat']

    elif node == 'policy':
        config_path = ['policy']
    else:
        config_path = ['firewall']
        if family:
            config_path += [family]
            if hook:
                config_path += [hook]
                if priority:
                    config_path += [priority]

    node_config = conf.get_config_dict(config_path, key_mangling=('-', '_'),
                                get_first_key=True, no_tag_node_value_mangle=True)

    return node_config
def get_nftables_details(family, hook, priority):
    if family == 'ipv6':
        suffix = 'ip6'
        name_prefix = 'NAME6_'
        aux='IPV6_'
    elif family == 'ipv4':
        suffix = 'ip'
        name_prefix = 'NAME_'
        aux=''
    else:
        suffix = 'bridge'
        name_prefix = 'NAME_'
        aux=''

    if hook == 'name' or hook == 'ipv6-name':
        command = f'sudo nft list chain {suffix} vyos_filter {name_prefix}{priority}'
    else:
        up_hook = hook.upper()
        command = f'sudo nft list chain {suffix} vyos_filter VYOS_{aux}{up_hook}_{priority}'

    try:
        results = cmd(command)
    except:
        return {}

    out = {}
    for line in results.split('\n'):
        comment_search = re.search(rf'{priority}[\- ](\d+|default-action)', line)
        if not comment_search:
            continue

        rule = {}
        rule_id = comment_search[1]
        counter_search = re.search(r'counter packets (\d+) bytes (\d+)', line)
        if counter_search:
            rule['packets'] = counter_search[1]
            rule['bytes'] = counter_search[2]

        rule['conditions'] = re.sub(r'(\b(counter packets \d+ bytes \d+|drop|reject|return|log)\b|comment "[\w\-]+")', '', line).strip()
        out[rule_id] = rule
    return out

def get_nftables_state_details(family):
    if family == 'ipv6':
        suffix = 'ip6'
        name_suffix = 'POLICY6'
    elif family == 'ipv4':
        suffix = 'ip'
        name_suffix = 'POLICY'
    else:
        # no state policy for bridge
        return {}

    command = f'nft list chain {suffix} vyos_filter VYOS_STATE_{name_suffix}'
    try:
        results = cmd(command)
    except:
        return {}

    out = {}
    for line in results.split('\n'):
        rule = {}
        for state in ['established', 'related', 'invalid']:
            if state in line:
                counter_search = re.search(r'counter packets (\d+) bytes (\d+)', line)
                if counter_search:
                    rule['packets'] = counter_search[1]
                    rule['bytes'] = counter_search[2]
                rule['conditions'] = re.sub(r'(\b(counter packets \d+ bytes \d+|drop|reject|return|log)\b|comment "[\w\-]+")', '', line).strip()
                out[state] = rule
    return out

def show_firewall(raw: bool = False, **kwargs):
    """
    Fetch firewall rulesets information with proper structure.
    """
    conf = Config()
    firewall = get_config_node(conf)

    if not firewall:
        return {}

    if raw:
        # Create a separate result structure instead of modifying the original config
        result = {
            "config": firewall,  # Keep original config intact
            "statistics": {}     # Add statistics in their own section
        }
        
        # Process each family
        for family in ['ipv4', 'ipv6', 'bridge']:
            family_stats = {}
            
            # Get state policy statistics if configured
            if 'global_options' in firewall and 'state_policy' in firewall['global_options']:
                state_details = get_nftables_state_details(family)
                if state_details:  # Only add if we got data
                    family_stats["state_policy"] = state_details
            
            # Get ruleset statistics
            ruleset_stats = {}
            if family in firewall:
                for hook, hook_conf in firewall[family].items():
                    for prior, prior_conf in hook_conf.items():
                        details = get_nftables_details(family, hook, prior)
                        if details:  # Only add if we got data
                            ruleset_stats[prior] = {
                                "hook": hook, 
                                "rules": details
                            }
            
            # Only add rulesets if we have data
            if ruleset_stats:
                family_stats["rulesets"] = ruleset_stats
                
            # Only add this family if we have any stats
            if family_stats:
                result["statistics"][family] = family_stats
        
        
        return result
    else:
        print("This function is implemented for GraphQL raw output only!")
        return {}
def get_firewall_statistics_dict(family, hook, prior, prior_conf, single_rule_id=None):
    """
    Create a structured dictionary from firewall rule information
    for API responses or JSON output
    """
    details = get_nftables_details(family, hook, prior)
    result = {
        "name": prior,
        "hook": hook,
        "family": family,
        "rules": {}
    }

    # Process regular rules
    if 'rule' in prior_conf:
        for rule_id, rule_conf in prior_conf['rule'].items():
            if single_rule_id and rule_id != single_rule_id:
                continue

            if 'disable' in rule_conf:
                continue

            # Create rule dictionary
            rule_dict = {
                "description": rule_conf.get('description', ''),
                "action": rule_conf.get('action', ''),
                "source": {
                    "address": "any"
                },
                "destination": {
                    "address": "any"
                },
                "inbound_interface": "any",
                "outbound_interface": "any",
                "statistics": {
                    "packets": 0,
                    "bytes": 0
                }
            }

            # Get source information
            source_addr = dict_search_args(rule_conf, 'source', 'address')
            if source_addr:
                rule_dict["source"]["address"] = source_addr
            else:
                # Check for group source address types
                for group_type in ['address_group', 'network_group', 'domain_group']:
                    group_addr = dict_search_args(rule_conf, 'source', 'group', group_type)
                    if group_addr:
                        rule_dict["source"]["group"] = {
                            "type": group_type,
                            "name": group_addr
                        }
                        break
                
                # Check for FQDN source
                fqdn = dict_search_args(rule_conf, 'source', 'fqdn')
                if fqdn:
                    rule_dict["source"]["fqdn"] = fqdn
                
                # Check for GeoIP source
                geoip = dict_search_args(rule_conf, 'source', 'geoip', 'country_code')
                if geoip:
                    codes = str(geoip)[1:-1].replace("'", "")
                    rule_dict["source"]["geoip"] = {
                        "country_code": codes,
                        "inverse_match": 'inverse_match' in dict_search_args(rule_conf, 'source', 'geoip')
                    }

            # Get destination information
            dest_addr = dict_search_args(rule_conf, 'destination', 'address')
            if dest_addr:
                rule_dict["destination"]["address"] = dest_addr
            else:
                # Check for group destination address types
                for group_type in ['address_group', 'network_group', 'domain_group']:
                    group_addr = dict_search_args(rule_conf, 'destination', 'group', group_type)
                    if group_addr:
                        rule_dict["destination"]["group"] = {
                            "type": group_type,
                            "name": group_addr
                        }
                        break
                
                # Check for FQDN destination
                fqdn = dict_search_args(rule_conf, 'destination', 'fqdn')
                if fqdn:
                    rule_dict["destination"]["fqdn"] = fqdn
                
                # Check for GeoIP destination
                geoip = dict_search_args(rule_conf, 'destination', 'geoip', 'country_code')
                if geoip:
                    codes = str(geoip)[1:-1].replace("'", "")
                    rule_dict["destination"]["geoip"] = {
                        "country_code": codes,
                        "inverse_match": 'inverse_match' in dict_search_args(rule_conf, 'destination', 'geoip')
                    }

            # Get interface information
            iiface = dict_search_args(rule_conf, 'inbound_interface', 'name')
            if iiface:
                rule_dict["inbound_interface"] = iiface
            else:
                iiface_group = dict_search_args(rule_conf, 'inbound_interface', 'group')
                if iiface_group:
                    rule_dict["inbound_interface"] = {
                        "group": iiface_group
                    }

            oiface = dict_search_args(rule_conf, 'outbound_interface', 'name')
            if oiface:
                rule_dict["outbound_interface"] = oiface
            else:
                oiface_group = dict_search_args(rule_conf, 'outbound_interface', 'group')
                if oiface_group:
                    rule_dict["outbound_interface"] = {
                        "group": oiface_group
                    }

            # Get statistics
            if rule_id in details:
                rule_details = details[rule_id]
                rule_dict["statistics"] = {
                    "packets": int(rule_details.get('packets', 0)),
                    "bytes": int(rule_details.get('bytes', 0))
                }
                if 'conditions' in rule_details:
                    rule_dict["conditions"] = rule_details['conditions']
            
            # Add protocol if specified
            if 'protocol' in rule_conf:
                rule_dict["protocol"] = rule_conf['protocol']
            
            # Store rule in result dictionary
            result["rules"][rule_id] = rule_dict

    # Add default action rule
    if hook in ['input', 'forward', 'output']:
        default_action = prior_conf.get('default_action', 'accept')
    else:
        default_action = prior_conf.get('default_action', 'drop')
    
    default_rule = {
        "action": default_action,
        "source": {"address": "any"},
        "destination": {"address": "any"},
        "inbound_interface": "any",
        "outbound_interface": "any",
        "statistics": {
            "packets": 0,
            "bytes": 0
        }
    }
    
    if 'default-action' in details:
        rule_details = details['default-action']
        default_rule["statistics"] = {
            "packets": int(rule_details.get('packets', 0)),
            "bytes": int(rule_details.get('bytes', 0))
        }
        if 'conditions' in rule_details:
            default_rule["conditions"] = rule_details['conditions']
    
    result["default_action"] = default_rule
    
    # Add description if available
    if 'description' in prior_conf:
        result["description"] = prior_conf['description']
        
    return result
def show_statistics(raw: bool = False, **kwargs):
    """
    Show firewall statistics in dictionary format suitable for JSON conversion
    
    Args:
        family: Optional filter by family (ipv4, ipv6, bridge)
        hook: Optional filter by hook (name, input, forward, output)
        ruleset: Optional filter by ruleset name
        
    Returns:
        dict: Structured dictionary with firewall statistics
    """
    conf = Config()
    firewall = get_config_node(conf)

    if not firewall:
        return {"statistics": {}}
    
    # Initialize result dictionary
    result = {"statistics": {}}
    
    # Determine which families to process
    families =  ['ipv4', 'ipv6', 'bridge']
    
    if raw:
    # Process each family
        for fam in families:
            if fam not in firewall:
                continue
            
            result['statistics'][fam] = {}
        
            # Add state policy statistics if configured
            if 'global_options' in firewall and 'state_policy' in firewall['global_options']:
                state_details = get_nftables_state_details(fam)
                if state_details:
                    result['statistics'][fam]['state_policy'] = state_details
        
            # Process each hook
            hooks =  firewall[fam].keys()
        
            for h in hooks:
                if h not in firewall[fam]:
                    continue
                
                result['statistics'][fam][h] = {}
            
                # Process each ruleset
                rulesets =  firewall[fam][h].keys()
            
                for rs in rulesets:
                    if rs not in firewall[fam][h]:
                        continue
                    
                    rs_conf = firewall[fam][h][rs]
                
                    # Generate dictionary for this ruleset using the existing function
                    ruleset_data = get_firewall_statistics_dict(fam, h, rs, rs_conf)
                    result['statistics'][fam][h][rs] = ruleset_data
    
        return result
    else:
        print("This function is implemented for GraphQL raw output only!")
        return {}

if __name__ == '__main__':
    print(show_statistics(raw=True))
