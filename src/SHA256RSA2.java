import org.json.JSONObject;
import org.junit.Assert;
import org.junit.Test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;


public class SHA256RSA2 {

    private static String keyPk = "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC6DAERacIFrEew" +
            "Lftxai5kTARygaGz/AiZJ3cXRhMxccCtnHeZRx0Hjf1SOc7nXj6+0RNJnXyTwE39" +
            "6gzuQRoN2186kqUSHV38cs79xeEAwMuEQiL9PcGZHbgFqQvsBrq0WX6TKkApcX87" +
            "8mVqYEjb1tYhBqQ1Tx01QpCar99QzHMK/rOJwc3wHIrqVqEjI0oGN55heoKzJxpg" +
            "n7p/XSa2tpZcNI4HLe16sj9vzkuyvV/GgTom1np7TRfqN9fQ+s4yJP4B4D6hTOvM" +
            "/7M3e87JBQwuvc2Bw/fkGX5nqmgOxauIDOd46vsnPHBCneD6kodxdVKzUMTvcV5N" +
            "dutY2otlAgMBAAECggEBALFvF2mrCl7ssqYlBIRi9wGyuh8W4MhN20ltqReqPk3O" +
            "pistaabmepok4e8UsO5aJM9JiPKRXyluozNBj7l+n0GN8aFkEEhZd7R3LlA6818L" +
            "gE2P4dzRlBzaihHj6jndJR0xqRTjm7OqyeS7RduRHouDtk5jDiLFZB7ScCUHDJz5" +
            "7zGghoTcZJFS8rnOXY8loB0yn2+gM82h8DDrg4ItWB/FdQPEKYAOXF9ib1bNM/Gx" +
            "G+QLo2/5IvmkHmbnaqMs8I69Ap5HRhRZJRaJWI8YqRmS2JN/7hFlyMn+VmttB8g3" +
            "74L3nzr+zAUl6OX5b1x5NyjY18i9mJf7pHvkoyEfKkECgYEA41+ThSvlE8gj4MCI" +
            "JTjy/Oh6My5GTS979sFO4oLxtbgRSPkDeMiFdjf97iOBhz1H8X+2oumP9E+3wjdA" +
            "PfGexB4aWJhatblN8NgKuVT/2ujaHeCTplzFRf/5PVOHQp1na3CcFpXCNOE4pVf9" +
            "mOIKN7O+rpO5+LHsUZK3GaMDSbECgYEA0XhxhmE5qMEVKLRDzHPcM3cCT8kpNcXm" +
            "Ef6cJsc7cQGrjal4jLCVWmPp9y1XcS7x9QpFBUMt5XCGBTdp90mDH2PbuBRmI5Tq" +
            "c0ntPBIx/32KfUz6mSqOv2RMrw1Mr19B90GcS9QbafdzC/h7GC3tNHVrHKXxL82F" +
            "6ob/kf0hlfUCgYEAwJpmoSlUrFQeKDWPXlCGbLwVP6OUQ6/Uh2qqgu+/Blq8sZ7W" +
            "VQsvGrxFauNCxqefeK/hqtDEc4TPuUIKNi6leaWyVZgBRuyIXFr1gpbBANO8aBCj" +
            "ogn1xd0WaN+HtWMWhwll/y+uyhJ6ZH1LwaTAWPz2qnVS1JsK/vKUDbBriZECgYBN" +
            "P9bWEPr7oiFUfo5WUxANJsGCfRQmkZIUZspdfrIMLep/dtVPRTv/NsOs9Vq/EeoH" +
            "TT9A/pJpgALc35/Do6eopuH71AIK8zs3QzcrJSatKzYsmXv9inVUXf/tusDiGAYy" +
            "0k56pIFrpecWrg9vTlihNQBIc2YsE+ZkJF8SDsEZFQKBgQCV64s4SQzCpaSWd9xw" +
            "l5QNjIGb8VDqOu3qAZt7EutcYDanGz92MP8yN8Odd42GP9CyL1JhhKd6gDgFJZvs" +
            "zTw84nzgqfv6hEuea/Yz2e9X84Hxgbff0IdduSvcgx33wOzfb5ldx+JU1Pxt8ske" +
            "WT8Iv4/3IFiWmr9O1vllbpI9Rg==";

    private static String keyPub = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAugwBEWnCBaxHsC37cWou" +
            "ZEwEcoGhs/wImSd3F0YTMXHArZx3mUcdB439UjnO514+vtETSZ18k8BN/eoM7kEa" +
            "DdtfOpKlEh1d/HLO/cXhAMDLhEIi/T3BmR24BakL7Aa6tFl+kypAKXF/O/JlamBI" +
            "29bWIQakNU8dNUKQmq/fUMxzCv6zicHN8ByK6lahIyNKBjeeYXqCsycaYJ+6f10m" +
            "traWXDSOBy3terI/b85Lsr1fxoE6JtZ6e00X6jfX0PrOMiT+AeA+oUzrzP+zN3vO" +
            "yQUMLr3NgcP35Bl+Z6poDsWriAzneOr7JzxwQp3g+pKHcXVSs1DE73FeTXbrWNqL" +
            "ZQIDAQAB";

    private static String REQUEST_TARGET = "(request-target)";

    private static String DATE = "Date";

    private static String DIGEST = "Digest";

    private static String GET = "get";

    private static String POST = "post";

    private static String PUT = "put";

    private static String DELETE = "delete";

    private static String PUBLIC = "PUBLIC";

    private static String URL = "https://staging.authservices.satispay.com/wally-services/protocol/tests/signature";

    private static String PAYLOAD = "hello world";;


    public String stringSignatureConstruction(String method,Map<String,String> headers) throws Exception{
        StringBuilder input = new StringBuilder();


        for (Map.Entry<String, String> entry : headers.entrySet()) {
            /*if (entry.getKey().equals(REQUEST_TARGET)) {
                input.append(REQUEST_TARGET).append(": ").append(headers.get(REQUEST_TARGET));
            }else if (entry.getKey().equals(DATE)) {
                final String stringToday = DateTimeFormatter.RFC_1123_DATE_TIME.format(ZonedDateTime.now(ZoneId.of("GMT")));
                if (input.length() != 0) {
                    input.append("\n").append(DATE.toLowerCase()).append(": " + stringToday);
                }
            } else if (entry.getKey().equals(DIGEST)) {
                final byte[] digest = MessageDigest.getInstance("SHA-256").digest(PAYLOAD.getBytes());
                final String digestHeader = Base64.getEncoder().encodeToString(digest);
                if (input.length() != 0) {
                    input.append("\n").append(DIGEST.toLowerCase()).append(": " + digestHeader);
                }
            }*/
            input.append(entry.getKey().toLowerCase()).append(": ").append(entry.getValue()).append("\n");
        }
        input.setLength(input.length() - 1);
        return input.toString();
    }

    // Create base64 encoded signature using SHA256/RSA.

    private static String signSHA256RSA(String input) throws Exception {

        byte[] b1 = Base64.getDecoder().decode(keyPk);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(b1);
        KeyFactory kf = KeyFactory.getInstance("RSA");

        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(kf.generatePrivate(spec));
        privateSignature.update(input.getBytes("UTF-8"));
        byte[] s = privateSignature.sign();
        return Base64.getEncoder().encodeToString(s);
    }


    public JSONObject call(String input,String methodCall,Map<String,String> headers) throws Exception{

        String base64Signature = signSHA256RSA(input);
        URL url = new URL(URL);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod(methodCall.toUpperCase());
        con.setDoOutput(true);

        StringBuilder header = new StringBuilder();
        header.append("Signature keyId=\"signature-test-66289\",algorithm=\"rsa-sha256\",headers=\"");
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            header.append(entry.getKey().toLowerCase()).append(" ");
            if(entry.getKey().equals(DATE))
                con.setRequestProperty(DATE, entry.getValue());
            else if(entry.getKey().equals(DIGEST))
                con.setRequestProperty(DIGEST, entry.getValue());
        }
        header.append("\",signature=").append(base64Signature);
        con.setRequestProperty("Authorization", header.toString());

        BufferedReader in = new BufferedReader(
                new InputStreamReader(con.getInputStream()));
        String inputLine;
        StringBuffer response = new StringBuffer();
        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }

        in.close();
        con.disconnect();

        return new JSONObject(response.toString());
    }

    private void genericTest(String methodCall,String... headersString) throws Exception{
        genericTest(methodCall,null,headersString);
    }

    private void genericTest(String methodCall,Map<String,String> headersMap,String... headersString) throws Exception{

        byte[] b1 = Base64.getDecoder().decode(keyPub);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(b1);
        Map<String, String> headers = new HashMap<>();
        if(headersMap == null) {
            for (String item : headersString) {
                if (item.equals(DATE))
                    headers.put("Date", DateTimeFormatter.RFC_1123_DATE_TIME.format(ZonedDateTime.now(ZoneId.of("GMT"))));
                else if (item.equals(DIGEST)) {
                    final byte[] digest = MessageDigest.getInstance("SHA-256").digest(PAYLOAD.getBytes());
                    final String digestHeader = Base64.getEncoder().encodeToString(digest);
                    headers.put("Digest", digestHeader);
                } else if (item.equals(REQUEST_TARGET))
                    headers.put(item, methodCall + " " + "/wally-services/protocol/tests/signature");

            }
        }
        else{
            headers = headersMap;
        }
        String input = stringSignatureConstruction(methodCall,headers);
        JSONObject myResponse = call(input,methodCall,headers);
        Assert.assertEquals(input,myResponse.get("signed_string"));
        Assert.assertEquals(signSHA256RSA(myResponse.get("signed_string").toString()),signSHA256RSA(input));
        Assert.assertNotEquals(PUBLIC,myResponse.getJSONObject("authentication_key").get("role"));

        Signature sign = Signature.getInstance("SHA256withRSA");
        KeyFactory kf = KeyFactory.getInstance("RSA");
        sign.initVerify(kf.generatePublic(spec));
        sign.update(myResponse.get("signed_string").toString().getBytes(UTF_8));

        byte[] b2 = Base64.getDecoder().decode(myResponse.getJSONObject("signature").get("signature").toString());
        Assert.assertTrue(sign.verify(b2));
    }

    @Test
    public void testMinHeader() throws Exception{
        genericTest(GET,REQUEST_TARGET);

        genericTest(POST,REQUEST_TARGET);

        genericTest(PUT,REQUEST_TARGET);

        genericTest(DELETE,REQUEST_TARGET);
    }

    @Test
    public void testGetHeader() throws Exception{
        genericTest(GET,REQUEST_TARGET,DATE,DIGEST);
    }

    @Test
    public void testPostHeader() throws Exception{
        genericTest(GET,REQUEST_TARGET,DATE,DIGEST);

    }

    @Test
    public void testPutHeader() throws Exception{
        genericTest(GET,REQUEST_TARGET,DATE,DIGEST);
    }

    @Test
    public void testDeleteHeader() throws Exception{
        genericTest(GET,REQUEST_TARGET,DATE,DIGEST);
    }

    @Test
    public void testHeaderCustom() throws Exception{
        Map<String, String> headers = new HashMap<>();
        headers.put(DATE,DateTimeFormatter.RFC_1123_DATE_TIME.format(ZonedDateTime.now(ZoneId.of("GMT"))));
        headers.put(REQUEST_TARGET, GET + " " + "/wally-services/protocol/tests/signature");
        headers.put("Host","staging.authservices.satispay.com");
        genericTest(GET,headers,null);
    }

}