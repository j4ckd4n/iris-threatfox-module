import iris_interface.IrisInterfaceStatus as InterfaceStatus
from iris_interface.IrisModuleInterface import IrisModuleInterface, IrisModuleTypes

import iris_threatfox_module.IrisThreatFoxConfig as interface_conf
from iris_threatfox_module.threatfox_handler.threatfox_handler import ThreatFoxHandler

class IrisThreatFoxInterface(IrisModuleInterface):
  name = "IrisThreatFoxInterface"
  _module_name = interface_conf.module_name
  _module_description = interface_conf.module_description
  _interface_version = interface_conf.interface_version
  _module_version = interface_conf.module_version
  _pipeline_support = interface_conf.pipeline_support
  _pipeline_info = interface_conf.pipeline_info
  _module_configuration = interface_conf.module_configuration
  _module_type = IrisModuleTypes.module_processor

  def register_hooks(self, module_id: int):
    self.module_id = module_id
    module_conf = self.module_dict_conf

    status = self.register_to_hook(module_id=module_id, iris_hook_name="on_postload_ioc_create")
    if status.is_failure():
      self.log.error(status.get_message())
      self.log.error(status.get_data())
    else:
      self.log.info("Successfully registered on_postload_ioc_update hook")

    status = self.register_to_hook(module_id, iris_hook_name='on_manual_trigger_ioc', manual_hook_name='Get ThreatFox Insight')
    if status.is_failure():
      self.log.error(status.get_message())
      self.log.error(status.get_data())
    else:
      self.log.info("Successfully registered on_manual_trigger_ioc hook")
  
  def hooks_handler(self, hook_name: str, hook_ui_name: str, data: dict):
    self.log.info(f'Received {hook_name}')

    if hook_name in ['on_postload_ioc_create', 'on_postload_ioc_update', 'on_manual_trigger_ioc']:
      status = self._handle_ioc(data=data)
    else:
      self.log.critical(f'Received unsupported hook {hook_name}')
      return InterfaceStatus.I2Error(data=data, logs=list(self.message_queue))
    
    if status.is_failure():
      self.log.error(f'Encountered error processing hook {hook_name}')
      return InterfaceStatus.I2Error(data=data, logs=list(self.message_queue))
    
    self.log.info(f"Successfully processed hook {hook_name}")
    return InterfaceStatus.I2Success(data=data, logs=list(self.message_queue))
  
  def _handle_ioc(self, data) -> InterfaceStatus.IIStatus:
    threatfox_handler = ThreatFoxHandler(mod_config=self.module_dict_conf, server_config=self.server_dict_conf, logger=self.log)

    in_status = InterfaceStatus.IIStatus(code=InterfaceStatus.I2CodeNoError)

    for element in data:
      if element.ioc_type.type_name in ['domain', 'md5', 'sha1', 'sha256', 'sha512']:
        status = threatfox_handler.handle_ioc(ioc=element)
        in_status = InterfaceStatus.merge_status(in_status, status)
      elif 'ip-' in element.ioc_type.type_name:
        status = threatfox_handler.handle_ioc(ioc=element)
        in_status = InterfaceStatus.merge_status(in_status, status)
      else:
        self.log.error(f'IOC type {element.ioc_type.type_name} not handled by Threatfox Module. Skipping')
    
    return in_status(data=data)