# SPDX-FileCopyrightText: Copyright (c) 2024 Scott Shawcroft for Adafruit Industries
#
# SPDX-License-Identifier: MIT

"""Pure Python implementation of the Matter IOT protocol."""

from __future__ import annotations

import binascii
import hashlib
import json
import logging
import pathlib
import time
from typing import Any, Optional

from . import case, interaction_model, nonvolatile, session
from .device_types.utility.root_node import RootNode
from .message import Message
from .protocol import InteractionModelOpcode, ProtocolId, SecureProtocolOpcode
from .subscription import Subscription

__version__ = "0.0.0+auto.0"

# Configure module logger
logger = logging.getLogger(__name__)


class CircuitMatter:
    def __init__(
        self,
        socketpool: Optional[Any] = None,
        mdns_server: Optional[Any] = None,
        random_source: Optional[Any] = None,
        state_filename: str = "matter-device-state.json",
        vendor_id: int = 0xFFF4,
        product_id: int = 0x1234,
        product_name: str = "CircuitMatter Device",
    ) -> None:
        if socketpool is None:
            import socket

            socketpool = socket
        self.socketpool = socketpool

        if mdns_server is None:
            from circuitmatter.utility.mdns.avahi import Avahi

            mdns_server = Avahi()
        self.mdns_server = mdns_server

        if random_source is None:
            from circuitmatter.utility import random

            random_source = random
        self.random = random_source

        state_file = pathlib.Path(state_filename)
        if not state_file.exists():
            from circuitmatter import certificates

            initial_state = certificates.generate_initial_state(
                vendor_id, product_id, product_name, random_source
            )
            with open(state_filename, "w") as f:
                json.dump(initial_state, f, indent=1)

        self.nonvolatile = nonvolatile.PersistentDictionary(state_filename)

        for key in ["discriminator", "salt", "iteration-count", "verifier"]:
            if key not in self.nonvolatile:
                raise RuntimeError(f"Missing key {key} in state file")

        self.packet_buffer = memoryview(bytearray(1280))

        # Define the UDP IP address and port
        UDP_IP = "::"  # Listen on all available network interfaces
        self.UDP_PORT = 5541

        # Create the UDP socket
        self.socket = self.socketpool.socket(self.socketpool.AF_INET6, self.socketpool.SOCK_DGRAM)

        # Bind the socket to the IP and port
        self.socket.bind((UDP_IP, self.UDP_PORT))
        logger.info("Listening on UDP port %d", self.UDP_PORT)
        self.socket.setblocking(False)

        self._endpoints = {}
        self._next_endpoint = 0
        self.root_node = RootNode(
            random_source,
            self.mdns_server,
            self.UDP_PORT,
            vendor_id,
            product_id,
            version=__version__,
            product_name=product_name,
        )
        self.add_device(self.root_node)

        self.vendor_id = vendor_id
        self.product_id = product_id
        self.manager = session.SessionManager(self.random, self.socket, self.root_node.noc)

        if self.root_node.fabric_count == 0:
            self.start_commissioning()

    def start_commissioning(self) -> None:
        discriminator = self.nonvolatile["discriminator"]
        passcode = self.nonvolatile["passcode"]
        txt_records = {
            "PI": "",
            "PH": "33",
            "CM": "1",
            "D": str(discriminator),
            "CRI": "3000",
            "CRA": "4000",
            "T": "1",
            "VP": f"{self.vendor_id}+{self.product_id}",
        }
        from . import pase

        pase.show_qr_code(self.vendor_id, self.product_id, discriminator, passcode)
        logger.info("Manual code: %s", self.nonvolatile["manual_code"])
        instance_name = self.random.urandom(8).hex().upper()
        self.mdns_server.advertise_service(
            "_matterc",
            "_udp",
            self.UDP_PORT,
            txt_records=txt_records,
            instance_name=instance_name,
            subtypes=[
                f"_L{discriminator}._sub._matterc._udp",
                "_CM._sub._matterc._udp",
            ],
        )

    def add_cluster(self, endpoint: int, cluster: Any) -> None:
        if endpoint not in self._endpoints:
            self._endpoints[endpoint] = {}
            if endpoint > 0:
                self.root_node.descriptor.PartsList.append(endpoint)
            self._next_endpoint = max(self._next_endpoint, endpoint + 1)
        self._endpoints[endpoint][cluster.CLUSTER_ID] = cluster

    def add_device(self, device: Any) -> None:
        self._endpoints[self._next_endpoint] = {}
        if self._next_endpoint > 0:
            self.root_node.descriptor.PartsList.append(self._next_endpoint)

        for server in device.servers:
            device.descriptor.ServerList.append(server.CLUSTER_ID)
            server.endpoint = self._next_endpoint
            self.add_cluster(self._next_endpoint, server)
        self.add_cluster(self._next_endpoint, device.descriptor)

        if "devices" not in self.nonvolatile:
            self.nonvolatile["devices"] = {}
        if device.name not in self.nonvolatile["devices"]:
            self.nonvolatile["devices"][device.name] = {}
        device.restore(self.nonvolatile["devices"][device.name])
        self._next_endpoint += 1

    def process_packets(self) -> None:
        while True:
            try:
                nbytes, addr = self.socket.recvfrom_into(
                    self.packet_buffer, len(self.packet_buffer)
                )
            except BlockingIOError:
                break
            if nbytes == 0:
                break

            self.process_packet(addr, self.packet_buffer[:nbytes])
        # Do any retransmits or subscriptions
        self.manager.send_packets()

    def _build_attribute_error(self, path: Any, status_code: Any) -> Any:
        report = interaction_model.AttributeReportIB()
        astatus = interaction_model.AttributeStatusIB()
        astatus.Path = path
        status = interaction_model.StatusIB()
        status.Status = status_code
        status.ClusterStatus = 0
        astatus.Status = status
        report.AttributeStatus = astatus
        return report

    def get_report(self, context, cluster, path, subscription=None):
        reports = []
        datas = cluster.get_attribute_data(context, path, subscription=subscription)
        for data in datas:
            report = interaction_model.AttributeReportIB()
            report.AttributeData = data
            reports.append(report)
        # Only add status if an error occurs
        if not datas:
            logger.warning("Unsupported attribute - cluster=%s, path=%s", cluster, path)
            report = self._build_attribute_error(
                path, interaction_model.StatusCode.UNSUPPORTED_ATTRIBUTE
            )
            reports.append(report)
        return reports

    def invoke(self, session, cluster, path, fields, command_ref):
        logger.debug("Invoking command - path=%s", path)
        response = interaction_model.InvokeResponseIB()
        cdata = cluster.invoke(session, path, fields)
        if isinstance(cdata, interaction_model.CommandDataIB):
            if command_ref is not None:
                cdata.CommandRef = command_ref
            response.Command = cdata
        else:
            cstatus = interaction_model.CommandStatusIB()
            cstatus.CommandPath = path
            status = interaction_model.StatusIB()
            if cdata is None:
                status.Status = interaction_model.StatusCode.UNSUPPORTED_COMMAND
                logger.warning("Unsupported command - path=%s", path)
            else:
                status.Status = cdata
            cstatus.Status = status
            if command_ref is not None:
                cstatus.CommandRef = command_ref
            response.Status = cstatus
            return response

        return response

    def read_attribute_path(self, context, path, subscription=None):
        attribute_reports = []
        if path.Endpoint is None:
            endpoints = self._endpoints
        else:
            endpoints = [path.Endpoint]

        # Wildcard so we get it from every endpoint.
        for endpoint in endpoints:
            temp_path = path.copy()
            temp_path.Endpoint = endpoint
            if path.Cluster is None:
                clusters = self._endpoints[endpoint].values()
            else:
                if path.Cluster not in self._endpoints[endpoint]:
                    logger.debug("Cluster 0x%02x not found on endpoint %d", path.Cluster, endpoint)
                    continue
                clusters = [self._endpoints[endpoint][path.Cluster]]
            for cluster in clusters:
                temp_path.Cluster = cluster.CLUSTER_ID
                attribute_reports.extend(
                    self.get_report(context, cluster, temp_path, subscription=subscription)
                )
        return attribute_reports

    def process_packet(self, address, data):  # noqa: PLR0912, PLR0914, PLR0915 Too many branches, statements and locals
        # Print the received data and the address of the sender
        # This is section 4.7.2
        message = Message()
        message.decode(data)
        message.source_ipaddress = address
        session_context = self.manager.get_session(message)
        if message.secure_session:
            if session_context is None:
                logger.warning("Failed to find session for message %d. Ignoring.", message.message_counter)
                return
            secure_session_context = session_context

        session_context.receive(message)
        if message.secure_session:
            secure_session_context = None
            if message.session_id < len(self.manager.secure_session_contexts):
                secure_session_context = self.manager.secure_session_contexts[message.session_id]
            if secure_session_context is None:
                logger.warning("Failed to find secure session context for session %d. Ignoring.", message.session_id)
                return
            # Decrypt the payload
            if not secure_session_context.decrypt_and_verify(message):
                logger.warning("Failed to decrypt message %d. Ignoring.", message.message_counter)
                return
        message.parse_protocol_header()
        self.manager.mark_duplicate(message)

        exchange = self.manager.process_exchange(message)
        if exchange is None:
            logger.debug("Dropping message %d", message.message_counter)
            return
        else:
            logger.debug(
                "Processing message %d for exchange %d", message.message_counter, exchange.exchange_id
            )

        protocol_id = message.protocol_id
        protocol_opcode = message.protocol_opcode

        if protocol_id == ProtocolId.SECURE_CHANNEL:  # noqa: PLR1702 Too many nested blocks
            if protocol_opcode == SecureProtocolOpcode.MSG_COUNTER_SYNC_REQ:
                logger.debug("Received Message Counter Synchronization Request")
            elif protocol_opcode == SecureProtocolOpcode.MSG_COUNTER_SYNC_RSP:
                logger.debug("Received Message Counter Synchronization Response")
            elif protocol_opcode == SecureProtocolOpcode.PBKDF_PARAM_REQUEST:
                logger.debug("Received PBKDF Parameter Request")
                from . import pase

                # This is Section 4.14.1.2
                request = pase.PBKDFParamRequest.decode(message.application_payload)
                exchange.commissioning_hash = hashlib.sha256(b"CHIP PAKE V1 Commissioning")
                exchange.commissioning_hash.update(message.application_payload)
                if request.passcodeId == 0:
                    pass
                    # Send back failure
                    # response = StatusReport()
                    # response.GeneralCode
                # print(request)
                response = pase.PBKDFParamResponse()
                response.initiatorRandom = request.initiatorRandom

                # Generate a random number
                response.responderRandom = self.random.urandom(32)
                session_context = self.manager.new_context()
                response.responderSessionId = session_context.local_session_id
                exchange.secure_session_context = session_context
                session_context.peer_session_id = request.initiatorSessionId
                if not request.hasPBKDFParameters:
                    params = pase.Crypto_PBKDFParameterSet()
                    params.iterations = self.nonvolatile["iteration-count"]
                    params.salt = binascii.a2b_base64(self.nonvolatile["salt"])
                    response.pbkdf_parameters = params

                encoded = response.encode()
                exchange.commissioning_hash.update(encoded)
                exchange.send(response)

            elif protocol_opcode == SecureProtocolOpcode.PBKDF_PARAM_RESPONSE:
                logger.debug("Received PBKDF Parameter Response")
            elif protocol_opcode == SecureProtocolOpcode.PASE_PAKE1:
                from . import pase

                logger.debug("Received PASE PAKE1")
                pake1 = pase.PAKE1.decode(message.application_payload)
                pake2 = pase.PAKE2()
                verifier = binascii.a2b_base64(self.nonvolatile["verifier"])
                context = exchange.commissioning_hash.digest()
                del exchange.commissioning_hash

                cA, Ke = pase.compute_verification(self.random, pake1, pake2, context, verifier)
                exchange.cA = cA
                exchange.Ke = Ke
                exchange.send(pake2)
            elif protocol_opcode == SecureProtocolOpcode.PASE_PAKE2:
                logger.debug("Received PASE PAKE2")
                raise NotImplementedError("Implement SPAKE2+ prover")
            elif protocol_opcode == SecureProtocolOpcode.PASE_PAKE3:
                from . import pase

                logger.debug("Received PASE PAKE3")
                pake3 = pase.PAKE3.decode(message.application_payload)
                if pake3.cA != exchange.cA:
                    del exchange.cA
                    del exchange.Ke
                    logger.warning("cA mismatch - authentication failed")
                    error_status = session.StatusReport()
                    error_status.general_code = session.GeneralCode.FAILURE
                    error_status.protocol_id = ProtocolId.SECURE_CHANNEL
                    error_status.protocol_code = session.SecureChannelProtocolCode.INVALID_PARAMETER
                    exchange.send(error_status)
                else:
                    exchange.session.session_timestamp = time.monotonic()
                    status_ok = session.StatusReport()
                    status_ok.general_code = session.GeneralCode.SUCCESS
                    status_ok.protocol_id = ProtocolId.SECURE_CHANNEL
                    status_ok.protocol_code = (
                        session.SecureChannelProtocolCode.SESSION_ESTABLISHMENT_SUCCESS
                    )
                    exchange.send(status_ok)

                    # Fully initialize the secure session context we'll use going
                    # forwards.
                    secure_session_context = exchange.secure_session_context

                    # Compute session keys
                    pase.compute_session_keys(exchange.Ke, secure_session_context)
                    logger.info("PASE authentication succeeded")
            elif protocol_opcode == SecureProtocolOpcode.CASE_SIGMA1:
                logger.debug("Received CASE Sigma1")
                sigma1 = case.Sigma1.decode(message.application_payload)
                response = self.manager.reply_to_sigma1(exchange, sigma1)

                exchange.send(response)
            elif protocol_opcode == SecureProtocolOpcode.CASE_SIGMA2:
                logger.debug("Received CASE Sigma2")
            elif protocol_opcode == SecureProtocolOpcode.CASE_SIGMA3:
                logger.debug("Received CASE Sigma3")
                sigma3 = case.Sigma3.decode(message.application_payload)
                protocol_code = self.manager.reply_to_sigma3(exchange, sigma3)

                error_status = session.StatusReport()
                general_code = session.GeneralCode.FAILURE
                if protocol_code == session.SecureChannelProtocolCode.SESSION_ESTABLISHMENT_SUCCESS:
                    general_code = session.GeneralCode.SUCCESS
                error_status.general_code = general_code
                error_status.protocol_id = ProtocolId.SECURE_CHANNEL
                error_status.protocol_code = protocol_code
                exchange.send(error_status)
            elif protocol_opcode == SecureProtocolOpcode.CASE_SIGMA2_RESUME:
                logger.debug("Received CASE Sigma2 Resume")
            elif protocol_opcode == SecureProtocolOpcode.STATUS_REPORT:
                logger.debug("Received Status Report")
                report = session.StatusReport()
                report.decode(message.application_payload)
                logger.debug("Status report: %r", report)

                # Acknowledge the message because we have no further reply.
                if message.exchange_flags & session.ExchangeFlags.R:
                    exchange.send_standalone()
            elif protocol_opcode == SecureProtocolOpcode.ICD_CHECK_IN:
                logger.debug("Received ICD Check-in")
            elif protocol_opcode == SecureProtocolOpcode.MRP_STANDALONE_ACK:
                logger.debug("Received MRP Standalone Ack")
                logger.debug("Message: %r", message)
            else:
                logger.warning("Unhandled secure channel opcode: %s", protocol_opcode)
        elif message.protocol_id == ProtocolId.INTERACTION_MODEL:
            secure_session_context = self.manager.secure_session_contexts[message.session_id]
            if protocol_opcode == InteractionModelOpcode.READ_REQUEST:
                read_request = interaction_model.ReadRequestMessage.decode(
                    message.application_payload
                )
                attribute_reports = []
                for path in read_request.AttributeRequests:
                    logger.debug("Reading attribute path: %s", path)
                    attribute_reports.extend(self.read_attribute_path(secure_session_context, path))
                response = interaction_model.ReportDataMessage()
                response.SuppressResponse = True
                response.AttributeReports = attribute_reports
                exchange.send(response)
                exchange.close()
            elif protocol_opcode == InteractionModelOpcode.WRITE_REQUEST:
                logger.debug("Received Write Request")
                write_request = interaction_model.WriteRequestMessage.decode(
                    message.application_payload
                )
                write_responses = []
                for request in write_request.WriteRequests:
                    path = request.Path
                    if path.Cluster in self._endpoints[path.Endpoint]:
                        cluster = self._endpoints[path.Endpoint][path.Cluster]
                        write_responses.append(
                            cluster.set_attribute(secure_session_context, request)
                        )
                response = interaction_model.WriteResponseMessage()
                response.WriteResponses = write_responses
                exchange.send(response)
                exchange.close()

            elif protocol_opcode == InteractionModelOpcode.INVOKE_REQUEST:
                logger.debug("Received Invoke Request")
                invoke_request = interaction_model.InvokeRequestMessage.decode(
                    message.application_payload
                )
                for invoke in invoke_request.InvokeRequests:
                    path = invoke.CommandPath
                    invoke_responses = []
                    if path.Endpoint is None:
                        # Wildcard so we get it from every endpoint.
                        for endpoint in self._endpoints:
                            if path.Cluster in self._endpoints[endpoint]:
                                cluster = self._endpoints[endpoint][path.Cluster]
                                path.Endpoint = endpoint
                                invoke_responses.append(
                                    self.invoke(
                                        secure_session_context,
                                        cluster,
                                        path,
                                        invoke.CommandFields,
                                    )
                                )
                            else:
                                logger.debug("Cluster 0x%02x not found on endpoint", path.Cluster)
                    elif path.Cluster in self._endpoints[path.Endpoint]:
                        cluster = self._endpoints[path.Endpoint][path.Cluster]
                        invoke_responses.append(
                            self.invoke(
                                secure_session_context,
                                cluster,
                                path,
                                invoke.CommandFields,
                                invoke.CommandRef,
                            )
                        )
                    else:
                        logger.debug("Cluster 0x%02x not found on endpoint %d", path.Cluster, path.Endpoint)
                response = interaction_model.InvokeResponseMessage()
                response.SuppressResponse = False
                response.InvokeResponses = invoke_responses
                exchange.send(response)
                exchange.close()
            elif protocol_opcode == InteractionModelOpcode.INVOKE_RESPONSE:
                logger.debug("Received Invoke Response")
            elif protocol_opcode == InteractionModelOpcode.SUBSCRIBE_REQUEST:
                logger.debug("Received Subscribe Request")
                subscribe_request = interaction_model.SubscribeRequestMessage.decode(
                    message.application_payload
                )
                subscription = Subscription(
                    exchange.exchange_id,
                    secure_session_context,
                    subscribe_request.MinIntervalFloor,
                    subscribe_request.MaxIntervalCeiling,
                )
                attribute_reports = []
                for path in subscribe_request.AttributeRequests:
                    attribute_reports.extend(
                        self.read_attribute_path(
                            secure_session_context, path, subscription=subscription
                        )
                    )
                response = interaction_model.ReportDataMessage()
                response.SubscriptionId = subscription.id
                response.AttributeReports = attribute_reports
                exchange.send(response)
                final_response = interaction_model.SubscribeResponseMessage()
                final_response.SubscriptionId = subscription.id
                final_response.MaxInterval = subscribe_request.MaxIntervalCeiling
                exchange.queue(final_response)
            elif protocol_opcode == InteractionModelOpcode.STATUS_RESPONSE:
                status_response = interaction_model.StatusResponseMessage.decode(
                    message.application_payload
                )
                logger.debug(
                    "Received Status Response on %d/%d ack %d: %r",
                    message.session_id, message.exchange_id,
                    message.acknowledged_message_counter, status_response.Status
                )

                # Acknowledge the message because we have no further reply.
                if message.exchange_flags & session.ExchangeFlags.R:
                    exchange.send_standalone()

                if exchange.pending_payloads:
                    if status_response.Status == interaction_model.StatusCode.SUCCESS:
                        exchange.send(exchange.pending_payloads.pop(0))
                    else:
                        exchange.pending_payloads.clear()
                        # Close after an error.
                        exchange.close()
                else:
                    # Close if nothing is pending.
                    exchange.close()

            else:
                logger.debug("Unhandled interaction model opcode - message: %r", message)
                logger.debug("Application payload: %s", message.application_payload.hex(" "))
        else:
            logger.warning("Unknown protocol %s with opcode %s", message.protocol_id, message.protocol_opcode)

        self.nonvolatile.commit()
        # TODO: Rollback on error?
