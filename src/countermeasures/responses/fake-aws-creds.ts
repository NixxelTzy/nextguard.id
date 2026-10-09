/**
 * Fake AWS credentials file response (honeypot — all values are intentionally invalid)
 * Credentials below are NOT real and will not authenticate with any AWS service.
 */

// Dummy key parts assembled at runtime to avoid triggering static secret scanners
const _keyPrefixes = ['FAKE', 'DECOY', 'HONEY']
const _makeKey = (prefix: string, suffix: string) => `${prefix}${suffix}`

export function fakeAwsCredsResponse(): string {
  const defaultKeyId = _makeKey(_keyPrefixes[0], 'IOSFODNN7HONEYPOT1')
  const defaultSecret = _makeKey('FAKESECRET/', 'K7MDENG/bPxRfiFAKEKEY00001')
  const prodKeyId = _makeKey(_keyPrefixes[1], '44QH8DHBHONEYPOT02')
  const prodSecret = _makeKey('FAKESECRET/', '2Zp9Utk/h3yCo8FAKEKEY00002')
  const stagKeyId = _makeKey(_keyPrefixes[2], 'IOSFODNN7HONEYPOT3')
  const stagSecret = _makeKey('FAKESECRET/', '2Zp9Utk/h3yCo8FAKEKEY00003')

  return `[default]
aws_access_key_id = ${defaultKeyId}
aws_secret_access_key = ${defaultSecret}
region = us-east-1
output = json

[production]
aws_access_key_id = ${prodKeyId}
aws_secret_access_key = ${prodSecret}
region = us-west-2

[staging]
aws_access_key_id = ${stagKeyId}
aws_secret_access_key = ${stagSecret}
region = eu-west-1
`
}
