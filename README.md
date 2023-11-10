# gateway-authentication-examples
Repository containing example code for different authentication methods.

### federated authentication
Using Federated authentication you need to send an assertion (jwt) in the request together with oauth credentials.
When using federated authentication you sign the assertion with a private key, and you have to provide an jwks endpoint with the corresponding public key, for validation of the assertion.

Example of how to create a signed jwt to use as assertion. This example takes bank and nnin as parameters, and put them in the jwt as claims. The different types of session requires different claims.
For example a customer session requires the claim "nnin". But a system session requires a username instead. The spesific need of claims for a partner to send will be set during the agreement and configuration phase.
The claim "bank" is only required if the integration includes more than one bank.
The assertion provider uses the `io.jsonwebtoken` library for creating and signing the jwt.
Explanation of the different claims can be found [here](https://tools.ietf.org/html/rfc7519#section-4.1)
```kotlin

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
```
Federated authentication also requires a jwks endpoint to be provided from the issuer of the assertion. This endpoint should return the public key used to sign the assertion. 
Example of how to create a jwks endpoint:

```kotlin

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
        jwks
      )
    )
  }
}

data class JsonWebKeySet(
  val keys: List<MutableMap<String, Any>> = listOf()
)
```
Both classes uses a common keyPair and keyId to make sure the key are the same in assertion as provided from jwks.

Example of a rest call to get the access_token using the assertion.
```bash
curl -X POST https://api-auth.test.sparebank1.no/oauth/token \ 
-H "Content-Type: application/x-www-form-urlencoded" \ 
-H "Authorization: Basic <base64 encoded client_id:client_secret>" \ 
-d "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer" \ 
-d "assertion=<assertion token (jwt)>"
```