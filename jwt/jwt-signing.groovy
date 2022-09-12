import com.google.gson.JsonObject;
import io.jsonwebtoken.*;
import java.text.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import org.json.*;

// get JWT secret key from params
String [] params = Parameters.split(",");
String secret_key = params[0];

// construct your body data - JSON entity in case below

JsonObject jo = new JsonObject();

jo.addProperty("param1", "PARAM_1");
jo.addProperty("param2", "PARAM_2");
jo.addProperty("param3", "PARAM_3");

String jsonString = jo.toString();

// perform JWT-signing of body data

byte[] bytesEncoded = Base64.encodeBase64(secret_key.getBytes());
String secret = new String(bytesEncoded);

try {
	String jwtToken = Jwts.builder()
	     .setHeaderParam("typ","JWT")
	     .setPayload(jsonString)
	     .signWith(SignatureAlgorithm.HS256, secret) 	// base64EncodedSecretKey
	     .compact();

	// put JWT-signed body data into variable
	vars.put("jwtToken", jwtToken);
} catch (Exception ex) {
	prev.setSuccessful(false);
	log.error(ex.getMessage());
	System.err.println(ex.getMessage());
}
