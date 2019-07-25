package dom.team.getprefs.wrappers

import dom.team.getprefs.`interface`.Wrapper

internal class PrefsWrapper : Wrapper {
    override fun encrypt(value: String) = value
    override fun decrypt(value: String) = value
}