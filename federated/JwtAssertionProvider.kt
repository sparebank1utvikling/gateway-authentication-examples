/**
 * Class for creating the assertion to send for authentication
 */
@Component
class JwtAssertionProvider(
  private val keyPair: KeyPair,
  private val environment: Environment,
  private val keyId: String
) {
  fun createSignedJwt(nnin: String, bank: String): String {

    val rsaPublicKey = keyPair.public as RSAPublicKey
    val headers = mapOf(
      "typ" to "JWT",
      "alg" to rsaPublicKey.algorithm,
      "kid" to keyId
    )

    val privateKey = keyPair.private as RSAPrivateKey
    val ttl = environment.getRequiredProperty("truststore.jwt-ttl").toLong()
    val now = Date()

    return Jwts.builder()
      .setHeaderParams(headers)
      .setAudience("https://api.sparebank1.no")
      .setIssuer("host to issuer application")
      .setIssuedAt(now)
      .setExpiration(Date(now.time + (ttl * 360)))
      .setNotBefore(now)
      .setSubject(nnin)
      .claim("bank", bank)
      .signWith(privateKey, SignatureAlgorithm.valueOf(environment.getRequiredProperty("truststore.algorithm")))
      .compact()
  }
}