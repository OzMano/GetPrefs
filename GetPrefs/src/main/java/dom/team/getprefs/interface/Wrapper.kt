package dom.team.getprefs.`interface`

interface Wrapper {
    /**
     * Method that returns the encrypted matching string
     * */
    fun encrypt(value: String): String

    /**
     * Method that returns the decrypted matching string
     * */
    fun decrypt(value: String): String
}