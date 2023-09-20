#!/usr/bin/env python3
#
#  IRIS Source Code
#  Copyright (C) 2021 - Airbus CyberSecurity (SAS)
#  ir@cyberactionlab.net
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public
#  License as published by the Free Software Foundation; either
#  version 3 of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with this program; if not, write to the Free Software Foundation,
#  Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

module_name = "IrisThreatFox"
module_description = "Provides an interface between ThreatFox and IRIS"
interface_version = "1.2.0"
module_version = "1.0"
pipeline_support = False
pipeline_info = {}

module_configuration = [
  {
    "param_name": "threatfox_ioc_template",
    "param_human_name": "ThreatFox IoC Template",
    "param_description": "Template for displaying IoCs",
    "default": '<div class="row"><div class="col-12"><h3>Basic Information</h3><dl class="row"><dt class="col-sm-3">Threat Type<dd class="col-sm-9">{{ threat_type }}<dt class="col-sm-3">Threat Type Description<dd class="col-sm-9">{{ threat_type_desc }}<dt class="col-sm-3">Malware Type<dd class="col-sm-9">{{ malware }}<dt class="col-sm-3">Malware Alias<dd class="col-sm-9">{{ malware_alias }}</dl></div></div>{% if malware_samples %}<div class="row"><div class="col-12"><h3>Additional Malware Samples</h3><dl class="row">{% for sample in malware_samples %}<dt class="col-sm-3">Timestamp<dd class="col-sm-9">{{ sample.time_stamp }}<dt class="col-sm-3">SHA256 Hash<dd class="col-sm-9">{{ sample.sha256_hash }}<dt class="col-sm-3">MD5 Hash<dd class="col-sm-9">{{ sample.md5_hash }}<dt class="col-sm-3">Malware Bazaar Link<dd class="col-sm-9">{{ sample.malware_bazaar }}</dd>{% endfor %}</dl></div></div>{% endif %}',
    "mandatory": False,
    "type": "textfield_html",
    "section": "Templates"
  }
]