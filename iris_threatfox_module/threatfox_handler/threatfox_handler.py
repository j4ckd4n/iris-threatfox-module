import traceback
import requests
import json

from iris_interface.IrisModuleInterface import IrisPipelineTypes, IrisModuleInterface, IrisModuleTypes
import iris_interface.IrisInterfaceStatus as InterfaceStatus
from app.datamgmt.manage.manage_attribute_db import add_tab_attribute_field

from iris_threatfox_module.threatfox_handler.threatfox_helper import gen_ioc_report_from_template

class ThreatFoxHandler(object):
  def __init__(self, mod_config, server_config, logger):
    self.mod_config = mod_config
    self.server_config = server_config
    self.log = logger
    
    self._url = "https://threatfox-api.abuse.ch/api/v1/"

  def handle_ioc(self, ioc):
    self.log.info(f'Getting report for {ioc.ioc_value}')

    data = {
      "query": "search_ioc",
      "search_term": ioc.ioc_value
    }
  
    res = requests.post(self._url, data=json.dumps(data))
    if res.status_code != 200:
      self.log.error(f'Failed to get data from ThreatFox. Status code {res.status_code}')
      return InterfaceStatus.I2Error(message=f"Failed to get data from ThreatFox. Status code {res.status_code}", data=res.content)
    
    content = res.json()
    if "no_result" in content['query_status']:
      self.log.error(f"IOC not found.")
      return InterfaceStatus.I2Error()
    
    content = content['data'][0]

    if content['tags']:
      self.log.info('Assigning tags to IOC.')
      if ioc.ioc_tags is None:
        ioc.ioc_tags = ""

      for tag in content['tags']:
        ioc.ioc_tags = f"{ioc.ioc_tags},{tag}"
    
    self.log.info('Adding new attribute ThreatFox Report to IoC')

    status = gen_ioc_report_from_template(html_template=self.mod_config.get('threatfox_ioc_template'), ioc_report=content)

    if not status.is_success():
      return status
    
    rendered_report = status.get_data()

    try:
      add_tab_attribute_field(ioc, tab_name="ThreatFox Report", field_name="HTML Report", field_type="html", field_value=rendered_report)
    except Exception:
      print(traceback.format_exc())
      self.log.error(traceback.format_exc())
      return InterfaceStatus.I2Error(traceback.format_exc())
    
    return InterfaceStatus.I2Success("Successfully processed IoC")