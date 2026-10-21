package org.pqchat.dht.protocol

import java.net.URLDecoder
import java.net.URLEncoder

/**
 * Helper data structure and serialization logic for geographic coordinate pins
 * and offline emergency/safety status messages embedded within BEP 44 micro-payloads.
 */
data class LocationPinData(
    val latitude: Double,
    val longitude: Double,
    val altitude: Double = 0.0,
    val accuracy: Float = 0.0f,
    val note: String = ""
) {
    /**
     * Standard RFC 5870 / Android 'geo:' URI for launching external offline maps
     * (e.g. OsmAnd, Organic Maps, Google Maps) with coordinates and labeled pin.
     */
    val geoUri: String
        get() = if (note.isNotBlank()) {
            val encodedNote = URLEncoder.encode(note, "UTF-8").replace("+", "%20")
            "geo:$latitude,$longitude?q=$latitude,$longitude($encodedNote)"
        } else {
            "geo:$latitude,$longitude?q=$latitude,$longitude"
        }

    /**
     * Compact URI representation stored inside encrypted text payload.
     */
    fun toPayloadText(): String {
        val encodedNote = URLEncoder.encode(note, "UTF-8").replace("+", "%20")
        return "geo:$latitude,$longitude?alt=$altitude&acc=$accuracy&note=$encodedNote"
    }

    companion object {
        fun parse(text: String?): LocationPinData? {
            if (text == null || !text.startsWith("geo:")) return null
            return try {
                val withoutScheme = text.removePrefix("geo:")
                val parts = withoutScheme.split("?")
                val coords = parts[0].split(",")
                if (coords.size < 2) return null
                val lat = coords[0].toDouble()
                val lon = coords[1].toDouble()
                var alt = 0.0
                var acc = 0.0f
                var note = ""

                if (parts.size > 1) {
                    val queryParams = parts[1].split("&")
                    for (param in queryParams) {
                        val kv = param.split("=")
                        if (kv.size == 2) {
                            when (kv[0]) {
                                "alt" -> alt = kv[1].toDoubleOrNull() ?: 0.0
                                "acc" -> acc = kv[1].toFloatOrNull() ?: 0.0f
                                "note" -> note = URLDecoder.decode(kv[1], "UTF-8")
                                "q" -> {
                                    if (note.isBlank()) {
                                        val qVal = URLDecoder.decode(kv[1], "UTF-8")
                                        val parenStart = qVal.indexOf('(')
                                        val parenEnd = qVal.lastIndexOf(')')
                                        if (parenStart != -1 && parenEnd > parenStart) {
                                            note = qVal.substring(parenStart + 1, parenEnd)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                LocationPinData(lat, lon, alt, acc, note)
            } catch (_: Exception) {
                null
            }
        }
    }
}

typealias LocationPinHelper = LocationPinData

