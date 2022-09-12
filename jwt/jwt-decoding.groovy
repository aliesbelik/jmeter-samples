import io.jsonwebtoken.*;
import java.text.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import org.json.*;

// get JWT secret key and response value (to check response against it) from params
String [] params = Parameters.split(",");
String secret_key = params[0];
String status = params[1];

byte[] bytesEncoded = Base64.encodeBase64(secret_key.getBytes());
String secret = new String(bytesEncoded);

try {
	// access response data
	String response = ctx.getPreviousResult().getResponseDataAsString();

	if (response.equals("")) {
		prev.setSuccessful(false);
		Failure = true;
		FailureMessage = "ERROR : Response is EMPTY.";
		throw new Exception("ERROR : Response is EMPTY.");
	} else {
	  	// perform decoding of JWT-signed response
		Claims claims = Jwts.parser().setSigningKey(secret).parseClaimsJws(response).getBody();		// base64EncodedSecretKey
		JwsHeader header = Jwts.parser().setSigningKey(secret).parseClaimsJws(response).getHeader();	// base64EncodedSecretKey
		String jwtResponse = claims.toString();

    		// OPTIONALLY: check any value against decoded response
		if (!jwtResponse.contains(status)) {
			prev.setSuccessful(false);
			Failure = true;
			FailureMessage = "ERROR: response doesn't contain " + status.toUpperCase();
		}

    		// OPTIONALLY: add to sampler's repsonse decoded equivalent of JWT-signed response data as well -
    		// to display in JMeter UI or to apply any assertions;
		StringBuilder fullResponse = new StringBuilder();
		fullResponse.append(prev.getResponseDataAsString());
		fullResponse.append("\n\n").append(jwtResponse);
		prev.setResponseData(fullResponse.toString());
	}
} catch (SignatureException e) {
	// don't trust the JWT!
	e.printStackTrace();
	prev.setSuccessful(false);
	log.error(e.getMessage());
	System.err.println(e.getMessage());
} catch (MalformedJwtException ex) {
	ex.printStackTrace();
	prev.setSuccessful(false);
	log.error(ex.getMessage());
	System.err.println(ex.getMessage());
}
