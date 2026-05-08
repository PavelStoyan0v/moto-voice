/*
* Copyright (C) 2025 Meshenger Contributors
* SPDX-License-Identifier: GPL-3.0-or-later
*/

package d.d.meshenger.call

import d.d.meshenger.AddressUtils
import d.d.meshenger.MainService
import d.d.meshenger.Settings
import java.net.*

/*
 * WebRTC initially exchanges an offer and answer via a signaling service.
 * The offer message contains a list of all IP addresses of the device in
 * the form of ICE candidates.
 * Since the signaling service is a direct IP connection for Meshenger
 * we can and want to avoid this leak of potentially private sensitive IP addresses.
*/

internal object RTCUtils
{
    const val disableFilter = true

    /*
    * Remove ICE candidate and connection line entries.
    *
    * The ICE candidates are a list of all IP addresses of the system.
    * This is default WebRTC behavior! We want to remove it.
    *
    * We instead let the receiver insert the senders/remote IP address,
    * see filterOfferAfterReception().
    */
    fun filterOfferBeforeSend(offer: String, remoteAddress: InetSocketAddress, settings: Settings): String {
        if (isTailscaleAddress(remoteAddress.address)) {
            return filterSdpToTailscaleCandidates(offer)
        }
        return stripSdpConnectionData(offer, remoteAddress)
    }

    /*
     * Add the senders/remote IP address as an ICE candidate.
     * This will then be used by WebRTC to establish a connection.
     *
    * See also filterOfferBeforeSend().
    */
    fun completeOfferAfterReception(offer: String, remoteAddress: InetSocketAddress, settings: Settings): String {
        if (isTailscaleAddress(remoteAddress.address)) {
            return offer
        }
        return completeSdpWithRemoteAddress(offer, remoteAddress)
    }

    fun filterAnswerBeforeSend(answer: String, remoteAddress: InetSocketAddress, settings: Settings): String {
        if (isTailscaleAddress(remoteAddress.address)) {
            return filterSdpToTailscaleCandidates(answer)
        }
        return stripSdpConnectionData(answer, remoteAddress)
    }

    fun completeAnswerAfterReception(answer: String, remoteAddress: InetSocketAddress, settings: Settings): String {
        if (isTailscaleAddress(remoteAddress.address)) {
            return answer
        }
        return completeSdpWithRemoteAddress(answer, remoteAddress)
    }

    private fun stripSdpConnectionData(sdp: String, remoteAddress: InetSocketAddress): String {
        if (disableFilter) {
            return sdp
        }

        if (remoteAddress.address.isLinkLocalAddress) {
            // Link-local addresses carry an interface scope that WebRTC does not accept here.
            return sdp
        }

        val filtered = mutableListOf<String>()
        for (line in sdp.lines()) {
            if (line.startsWith("a=candidate:")) {
                continue
            }

            if (line.startsWith("c=")) {
                continue
            }
            filtered.add(line)
        }

        return filtered.joinToString("\n")
    }

    private fun completeSdpWithRemoteAddress(sdp: String, remoteAddress: InetSocketAddress): String {
        if (disableFilter) {
            return sdp
        }

        if (remoteAddress.address.isLinkLocalAddress) {
            return sdp
        }

        val remoteAddressString = AddressUtils.stripHost(remoteAddress.address.toString())
        val iceUdp = "a=candidate:3333333333 1 udp 2222222222 $remoteAddressString ${MainService.SERVER_PORT + 1} typ host"
        val iceTcp = "a=candidate:4444444444 2 tcp 1111111111 $remoteAddressString ${MainService.SERVER_PORT + 1} typ host"
        val c = if (remoteAddress.address is Inet6Address) {
            "c=IN IP6 0.0.0.0"
        } else {
            "c=IN IP4 0.0.0.0"
        }
        val nl = if (sdp.endsWith("\n")) "" else "\n"
        return "${sdp}${nl}${iceUdp}\n${iceTcp}\n${c}\n"
    }

    private fun filterSdpToTailscaleCandidates(sdp: String): String {
        val tailscaleIpv4 = mutableSetOf<String>()
        val tailscaleIpv6 = mutableSetOf<String>()

        for (line in sdp.lines()) {
            if (!line.startsWith("a=candidate:")) {
                continue
            }

            val candidateAddress = extractCandidateAddress(line) ?: continue
            val inetAddress = AddressUtils.parseInetAddress(candidateAddress) ?: continue
            if (!isTailscaleAddress(inetAddress)) {
                continue
            }

            if (inetAddress is Inet6Address) {
                tailscaleIpv6.add(candidateAddress)
            } else {
                tailscaleIpv4.add(candidateAddress)
            }
        }

        if (tailscaleIpv4.isEmpty() && tailscaleIpv6.isEmpty()) {
            return sdp
        }

        val preferredIpv4 = tailscaleIpv4.firstOrNull()
        val preferredIpv6 = tailscaleIpv6.firstOrNull()
        val filtered = mutableListOf<String>()

        for (line in sdp.lines()) {
            when {
                line.startsWith("a=candidate:") -> {
                    val candidateAddress = extractCandidateAddress(line) ?: continue
                    if (candidateAddress in tailscaleIpv4 || candidateAddress in tailscaleIpv6) {
                        filtered.add(line)
                    }
                }
                line.startsWith("c=IN IP4 ") && preferredIpv4 != null -> {
                    filtered.add("c=IN IP4 $preferredIpv4")
                }
                line.startsWith("c=IN IP6 ") && preferredIpv6 != null -> {
                    filtered.add("c=IN IP6 $preferredIpv6")
                }
                else -> filtered.add(line)
            }
        }

        return filtered.joinToString("\n")
    }

    private fun extractCandidateAddress(line: String): String? {
        val tokens = line.split(" ")
        return if (tokens.size >= 5) tokens[4] else null
    }

    private fun isTailscaleAddress(address: InetAddress): Boolean {
        return when (address) {
            is Inet4Address -> {
                val bytes = address.address
                bytes[0].toInt() == 100 && (bytes[1].toInt() and 0xC0) == 0x40
            }
            is Inet6Address -> {
                val bytes = address.address
                bytes.size >= 6
                    && bytes[0] == 0xfd.toByte()
                    && bytes[1] == 0x7a.toByte()
                    && bytes[2] == 0x11.toByte()
                    && bytes[3] == 0x5c.toByte()
                    && bytes[4] == 0xa1.toByte()
                    && bytes[5] == 0xe0.toByte()
            }
            else -> false
        }
    }
}
