package dom.team.getprefs.exceptions

internal class GetPreferencesException internal constructor(x: Throwable, y: String) : RuntimeException("$y $x")