# php-json-web-token-util
This PHP class will encode/decode JSON web tokens with custom payloads.

**Example Usage:**

```
<?
  $response = ['status' => 200];

  $jwt = new Jwt('your super secret key string', 'exampledomain.com', 'exampledomain.com');
  $expireTime = 5 * 60;
  $payload = ['sub' => 'some user id,'exp' => time() + $expireTime];
  $token = $this->jwt->createToken($payload);

  $response['access_token'] = $this->jwt->createToken($payload);
  $response['token_type'] = 'Bearer';
  $response['expires_in'] = $expireTime;

  exit(json_encode($response));
?>
```
