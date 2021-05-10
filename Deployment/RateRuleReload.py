
import boto3
import json
import os
import logging

# This lambda function helps to configure Rate Based Rules in desired WebACLs (or) to modify rate based rule values
# of desired WebACLs.
#
# WebACL rate based rules are not governed by Firewall Manager, hence we need solution if we need to modify value 
# across multiple accounts in an multi-account architecture. This design is based on assumption that a separate 
# security account exists within your organization.
#
# Trigger Type: Custom Event bus or lambda payload.
#
# Customers can integrate their SaaS tool with AWS Cloudwatch event bus, thereby allowing changes to rate based rules.


def update_raterule(log, assumed_session, webacl_scope, webacl_name, webacl_id, policy_rbpostvalue, policy_rbgetvalue):
    wafv2_client = assumed_session.client('wafv2')
    webacl_response = wafv2_client.get_web_acl(
        Name=webacl_name,
        Scope=webacl_scope,
        Id=webacl_id
        )

    postRuleExists = False
    getHeadRuleExists = False
    ruleEditSuccess = False
    i = 0

    for rule in webacl_response['WebACL']['Rules']:
        if rule['Name'] == 'POSTRule':
            postRuleExists = True
            log.info('[RateBasedRule-Reload] POSTRule exists for WebACL: %s' %webacl_name)
            newvalue = {
                "Limit": int(policy_rbpostvalue)
            }
            try:
                webacl_response['WebACL']['Rules'][i]['Statement']['RateBasedStatement'].update(newvalue)
                log.info('[RateBasedRule-Reload] Successfully edited POSTRule for WebACL: %s to new value %s' %(webacl_name, policy_rbpostvalue))
                ruleEditSuccess = True
            except Exception as error:
                log.error(str(error))

        if rule['Name'] == 'GetHeadRule':
            getHeadRuleExists = True
            log.info('[RateBasedRule-Reload] GetHeadRule exists for WebACL: %s' %webacl_name)
            newvalue = {
                "Limit": int(policy_rbgetvalue)
            }
            try:
                webacl_response['WebACL']['Rules'][i]['Statement']['RateBasedStatement'].update(newvalue)
                log.info('[RateBasedRule-Reload] Successfully edited GetHeadRule for WebACL: %s to new value %s' %(webacl_name, policy_rbgetvalue))
                ruleEditSuccess = True
            except Exception as error:
                log.error(str(error))

        i = i + 1
    
    if ruleEditSuccess:
        updates = webacl_response['WebACL']['Rules']
        response_webacl = wafv2_client.get_web_acl(
            Name=webacl_name,
            Scope=webacl_scope,
            Id=webacl_id
        )
        
        try:
            wafv2_client.update_web_acl(
                Name=webacl_name,
                Scope=webacl_scope,
                Id=webacl_id,
                DefaultAction={
                    'Allow': {}
                },
                Rules=updates,
                VisibilityConfig={
                    'SampledRequestsEnabled': True,
                    'CloudWatchMetricsEnabled': True,
                    'MetricName': 'WebACL'
                },
                LockToken=response_webacl['LockToken']
            )
            log.info('[RateBasedRule-Reload] Successfully updated POSTRule & GetHeadRule for WebACL: %s' %webacl_name)
        except Exception as error:
            log.error(str(error))
        
    if not postRuleExists:
        log.info('[RateBasedRule-Reload] Adding PostRule for %s with value: %s' %(webacl_name, policy_rbpostvalue))
        webacl_response['WebACL']['Rules'].append({
            "Name": "POSTRule",
            "Priority": 0,
            "Statement": {
                "RateBasedStatement": {
                    "Limit": int(policy_rbpostvalue),
                    "AggregateKeyType": "IP",
                    "ScopeDownStatement": {
                        "ByteMatchStatement": {
                            "FieldToMatch": {
                                "Method": {}
                            },
                            "PositionalConstraint": "EXACTLY",
                            "SearchString": "POST",
                            "TextTransformations": [
                                {
                                    "Type": "NONE",
                                    "Priority": 0
                                }
                            ]
                        }
                    }
                }
            },
            'Action': {
                'Block': {}
            },
            'VisibilityConfig': {
                'SampledRequestsEnabled': True,
                'CloudWatchMetricsEnabled': True,
                'MetricName': 'RateRule-POST'
            }
        })
        updates = webacl_response['WebACL']['Rules']
        response_webacl = wafv2_client.get_web_acl(
            Name=webacl_name,
            Scope=webacl_scope,
            Id=webacl_id
        )
        try: 
            wafv2_client.update_web_acl(
                Name=webacl_name,
                Scope=webacl_scope,
                Id=webacl_id,
                DefaultAction={
                    'Allow': {}
                },
                Rules=updates,
                VisibilityConfig={
                    'SampledRequestsEnabled': True,
                    'CloudWatchMetricsEnabled': True,
                    'MetricName': 'WebACL'
                },
                LockToken=response_webacl['LockToken']
            )
            log.info('[RateBasedRule-Reload] Successfully added PostRule for %s' %webacl_name)
        except Exception as error:
            log.error(str(error))

    if not getHeadRuleExists:
        log.info('[RateBasedRule-Reload] Adding GetHeadRule for %s with value: %s' %(webacl_name, policy_rbgetvalue))
        webacl_response['WebACL']['Rules'].append({
            'Name': 'GetHeadRule',
            'Priority': 1,
            'Statement': {
                'RateBasedStatement': {
                    'Limit': int(policy_rbgetvalue),
                    'AggregateKeyType': 'IP',
                    "ScopeDownStatement": {
                        "OrStatement": {
                            "Statements": [
                                {
                                    "ByteMatchStatement": {
                                        "FieldToMatch": {
                                            "Method": {}
                                        },
                                        "PositionalConstraint": "CONTAINS",
                                        "SearchString": "GET",
                                        "TextTransformations": [
                                            {
                                                "Type": "NONE",
                                                "Priority": 0
                                            }
                                        ]
                                    }
                                },
                                {
                                    "ByteMatchStatement": {
                                        "FieldToMatch": {
                                            "Method": {}
                                        },
                                        "PositionalConstraint": "CONTAINS",
                                        "SearchString": "HEAD",
                                        "TextTransformations": [
                                            {
                                                "Type": "NONE",
                                                "Priority": 0
                                            }
                                        ]
                                    }
                                }
                            ]
                        }
                    }
                }
            },
            'Action': {
                'Block': {}
            },
            'VisibilityConfig': {
                'SampledRequestsEnabled': True,
                'CloudWatchMetricsEnabled': True,
                'MetricName': 'RateRule'
            }
        })
        updates = webacl_response['WebACL']['Rules']
        response_webacl = wafv2_client.get_web_acl(
            Name=webacl_name,
            Scope=webacl_scope,
            Id=webacl_id
        )

        try:
            wafv2_client.update_web_acl(
                Name=webacl_name,
                Scope=webacl_scope,
                Id=webacl_id,
                DefaultAction={
                    'Allow': {}
                },
                Rules=updates,
                VisibilityConfig={
                    'SampledRequestsEnabled': True,
                    'CloudWatchMetricsEnabled': True,
                    'MetricName': 'WebACL'
                },
                LockToken=response_webacl['LockToken']
            )
            log.info('[RateBasedRule-Reload] Successfully added GetHeadRule for %s' %webacl_name)
        except Exception as error:
            log.error(str(error))        

def get_webacl(log, scope_type, policy, assumed_session):
    # Setting up variables
    webacl_client = ''
    webacl_list = ''

    webacl_client = assumed_session.client('wafv2')
    webacl_list = webacl_client.list_web_acls(
        Scope=scope_type,
        Limit=100
    )
    
    # Append all webacls if it is more than 100
    loop_pointer = True
    nextmarker = webacl_list['NextMarker']

    while loop_pointer:
        temp_list = webacl_client.list_web_acls(
            Scope=scope_type,
            NextMarker=nextmarker,
            Limit=100
        )
        
        #print(temp_list)
        
        if temp_list['WebACLs']:
            webacl_list.append(temp_list)
            nextmarker = temp_list['NextMarker']
        
        if not temp_list['WebACLs']:
            #print('Breaking while loop')
            loop_pointer = ''
        
    #print(webacl_list)

    for policylist in range(len(policy)):
        policy_name = policy[policylist]['Name']
        policy_rbpostvalue = policy[policylist]['RateBasedPostValue']
        policy_rbgetvalue = policy[policylist]['RateBasedGetValue']
        fmspolicy_name = 'FMManagedWebACLV2' + str(policy_name)
        #print(fmspolicy_name)

        for webaclindex in range(len(webacl_list['WebACLs'])):
            wafArn = webacl_list['WebACLs'][webaclindex]['ARN']
            arn_split = (wafArn.split(':'))
            req = (arn_split[5])
            arn_split_2 = (req.split('/'))
            scope_lower = (arn_split_2[0])
            webacl_scope = scope_lower.upper()
            webacl_name = (arn_split_2[2])
            webacl_id = (arn_split_2[3])

            if wafArn.find('arn:aws:wafv2:') >= 0:
                if webacl_name.find(fmspolicy_name) >= 0:
                    log.info('[RateBasedRule-Reload] Applying RateBasedRule for %s' %webacl_name)
                    update_raterule(log, assumed_session, webacl_scope, webacl_name, webacl_id, policy_rbpostvalue, policy_rbgetvalue)
            
def handler(event, context):   
    log = logging.getLogger()
    # ------------------------------------------------------------------
    # Declare variables
    # ------------------------------------------------------------------
    accounts = {}
    region = ''
    role_arn = ''
    sec_account = str(os.getenv('SECURITY_ACCOUNT'))
    
    try:
        # ------------------------------------------------------------------
        # Set Log Level
        # ------------------------------------------------------------------
        log_level = str(os.getenv('LOG_LEVEL').upper())
        if log_level not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
            log_level = 'DEBUG'
        log.setLevel(log_level)

        log.info('[RateBasedRule-Reload] Start')
        # -------------------------------------------------------------------
        # Collect member accounts of the Organization 
        # -------------------------------------------------------------------    
        fms_client = boto3.client('fms')
        
        # If there are more than 100 AWS accounts, then collect all accounts using NextToken parameter
        accounts = fms_client.list_member_accounts(
            MaxResults=100
        )
        
        # Loop through all member accounts except security account itself
        for mem_account in accounts['MemberAccounts']:
            # Most customers use Security account only for managing security resources, hence ignoring it for updating WebACL.
            if mem_account != sec_account:
                for index in range(len(event['Scope'])):
                    scope_type = event['Scope'][index]['Type']
                    policy = event['Scope'][index]['Policy']
                    role_arn = "arn:aws:iam::{}:role/WAF-RateRule-Reload".format(mem_account)
        
                    sts_client = boto3.client('sts')
        
                    sts_response = sts_client.assume_role(
                        RoleArn=role_arn,
                        RoleSessionName='WafRateBasedRule'
                    )
        
                    credentials = sts_response['Credentials']
        
                    assumed_session = boto3.Session(
                        aws_access_key_id=credentials['AccessKeyId'],
                        aws_secret_access_key=credentials['SecretAccessKey'],
                        aws_session_token=credentials['SessionToken']
                    )
        
                    get_webacl(log, scope_type, policy, assumed_session)
    
    except Exception as error:
        log.error(str(error))
        raise

    log.info('[RateBasedRule-Reload] End')