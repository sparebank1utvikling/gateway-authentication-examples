/**
 * Controller class for providing JWKS endpoint to verify assertion
 */
@Controller
@RequestMapping("/auth/jwks")
class JwksController(
  private val keyPair: KeyPair,
  private val keyId: String,
  private val environment: Environment,
) {

  @GetMapping(produces = [MediaType.APPLICATION_JSON_VALUE])
  @ResponseBody
  fun getKeySet(): JsonWebKeySet {
    val rsaPublicKey = keyPair.public as RSAPublicKey
    val jwks = mutableMapOf<String, Any>(
      "kty" to rsaPublicKey.algorithm,
      "kid" to keyId,
      "n"   to Base64.getUrlEncoder().encodeToString(rsaPublicKey.modulus.toByteArray()),
      "e"   to Base64.getUrlEncoder().encodeToString(rsaPublicKey.publicExponent.toByteArray()),
      "alg" to environment.getRequiredProperty("truststore.algorithm"),
      "use" to "sig"
    )

    return JsonWebKeySet(
      listOf(
        values
      )
    )
  }
}

data class JsonWebKeySet(
  val keys: List<MutableMap<String, Any>> = listOf()
)