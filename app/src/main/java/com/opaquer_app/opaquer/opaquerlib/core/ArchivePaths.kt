package com.opaquer_app.opaquerlib.core

import java.text.Normalizer

/**
 * Path rules, fixed before the first write: NFC-normalised, case-sensitive, "/a/b" form,
 * no empty, "." or ".." segments.
 */
object ArchivePaths {
    const val ROOT = "/"

    fun folder(path: String): String {
        val segments = Normalizer.normalize(path, Normalizer.Form.NFC).split('/').filter { it.isNotEmpty() }
        segments.forEach(::checkSegment)
        return if (segments.isEmpty()) ROOT else segments.joinToString("/", prefix = "/")
    }

    fun name(name: String): String = Normalizer.normalize(name, Normalizer.Form.NFC).also(::checkSegment)

    /** Name of the direct child of [parent] on the way to [path], or null if [path] is not below [parent]. */
    fun childOf(parent: String, path: String): String? {
        val prefix = if (parent == ROOT) ROOT else "$parent/"
        if (!path.startsWith(prefix) || path.length == prefix.length) return null
        return path.substring(prefix.length).substringBefore('/')
    }

    private fun checkSegment(s: String) {
        require(s.isNotEmpty() && s != "." && s != ".." && '/' !in s && '\u0000' !in s) { "Invalid path segment '$s'" }
    }
}
