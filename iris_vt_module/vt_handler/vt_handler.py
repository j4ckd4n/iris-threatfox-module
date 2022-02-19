#!/usr/bin/env python3
#
#  IRIS VT Module Source Code
#  contact@dfir-iris.org
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
import logging
import traceback

from virus_total_apis import PublicApi, PrivateApi

from iris_interface.IrisModuleInterface import IrisPipelineTypes, IrisModuleInterface, IrisModuleTypes, log
import iris_interface.IrisInterfaceStatus as InterfaceStatus
from app.datamgmt.manage.manage_attribute_db import add_tab_attribute_field

from iris_vt_module.vt_handler.vt_helper import gen_domain_report_from_template, gen_ip_report_from_template


class VtHandler():
    def __init__(self, mod_config):
        self.mod_config = mod_config
        self.vt = self.get_vt_instance()

    def get_vt_instance(self):
        """
        Returns an VT API instance depending if the key is premium or not

        :return: VT Instance
        """
        is_premium = self.mod_config.get('vt_key_is_premium')
        api_key = self.mod_config.get('vt_api_key')

        if is_premium:
            return PrivateApi(api_key)
        else:
            return PublicApi(api_key)

    def handle_vt_domain(self, ioc):
        """
        Handles an IOC of type domain and adds VT insights

        :param ioc: IOC instance
        :return: IIStatus
        """

        log.info(f'Getting domain report for {ioc.ioc_value}')
        report = self.vt.get_domain_report(ioc.ioc_value)

        log.info(f'VT report fetched.')
        results = report.get('results')
        if not results:
            log.error(f'Unable to get report. Is the API key valid ?')
            return InterfaceStatus.I2Error

        if results.get('response_code') == 0:
            log.error(f'Got invalid feedback from VT :: {results.get("verbose_msg")}')
            return InterfaceStatus.I2Success()

        if self.mod_config.get('vt_domain_add_whois_as_desc') is True:
            if "WHOIS" not in ioc.ioc_description:
                log.info('Adding WHOIS information to IOC description')
                ioc.ioc_description = f"{ioc.ioc_description}\n\nWHOIS\n {report.get('results').get('whois')}"

            else:
                log.info('Skipped adding WHOIS. Information already present')
        else:
            log.info('Skipped adding WHOIS. Option disabled')

        if self.mod_config.get('vt_domain_add_subdomain_as_desc') is True:

            if "Subdomains" not in ioc.ioc_description:
                if report.get('results').get('subdomains'):
                    subd_data = [f"- {subd}\n" for subd in report.get('results').get('subdomains')]
                    log.info('Adding subdomains information to IOC description')
                    ioc.ioc_description = f"{ioc.ioc_description}\n\nSubdomains\n{subd_data}"
                else:
                    log.info('No subdomains in VT report')
            else:
                log.info('Skipped adding subdomains information. Information already present')
        else:
            log.info('Skipped adding subdomain information. Option disabled')

        if self.mod_config.get('vt_report_as_attribute') is True:
            log.info('Adding new attribute VT Domain Report to IOC')

            status = gen_domain_report_from_template(html_template=self.mod_config.get('vt_domain_report_template'),
                                                     vt_report=report.get('results'))

            if not status.is_success():
                return status

            rendered_report = status.get_data()

            try:
                add_tab_attribute_field(ioc, tab_name='VT Report', field_name="HTML report", field_type="html",
                                        field_value=rendered_report)

            except Exception:

                log.error(traceback.format_exc())
                return InterfaceStatus.I2Error(traceback.format_exc())
        else:
            log.info('Skipped adding attribute report. Option disabled')

        return InterfaceStatus.I2Success()

    def handle_vt_ip(self, ioc):
        """
        Handles an IOC of type IP and adds VT insights

        :param ioc: IOC instance
        :return: IIStatus
        """
        vt = self.get_vt_instance()

        log.info(f'Getting IP report for {ioc.ioc_value}')
        report = vt.get_ip_report(ioc.ioc_value)

        log.info(f'VT report fetched.')

        results = report.get('results')
        if not results:
            log.error(f'Unable to get report. Is the API key valid ?')
            return InterfaceStatus.I2Error

        if results.get('response_code') == 0:
            log.error(f'Got invalid feedback from VT :: {results.get("verbose_msg")}')
            return InterfaceStatus.I2Success

        log.info(f'Report results validated')

        if self.mod_config.get('vt_ip_assign_asn_as_tag') is True:
            log.info('Assigning new ASN tag to IOC.')

            asn = report.get('results').get('asn')
            if asn is None:
                log.info('ASN was nul - skipping')

            if f'ASN:{asn}' not in ioc.ioc_tags.split(','):
                ioc.ioc_tags = f"{ioc.ioc_tags},ASN:{asn}"
            else:
                log.info('ASN already tagged for this IOC. Skipping')

        if self.mod_config.get('vt_report_as_attribute') is True:
            log.info('Adding new attribute VT IP Report to IOC')

            status = gen_ip_report_from_template(html_template=self.mod_config.get('vt_ip_report_template'),
                                                 vt_report=report.get('results'))

            if not status.is_success():
                return status

            rendered_report = status.get_data()

            try:
                add_tab_attribute_field(ioc, tab_name='VT Report', field_name="HTML report", field_type="html",
                                        field_value=rendered_report)

            except Exception:

                log.error(traceback.format_exc())
                return InterfaceStatus.I2Error(traceback.format_exc())
        else:
            log.info('Skipped adding attribute report. Option disabled')

        return InterfaceStatus.I2Success("Successfully processed IP")