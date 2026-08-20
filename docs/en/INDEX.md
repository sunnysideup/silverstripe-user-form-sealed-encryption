# tl;dr

1. generate the `A` and `B` keys, locally, from the comand line: `vendor/bin/sake tasks:generate-sealed-box-keys`

2. save the `A key` on the server, in the `.env` file: `SS_SEALED_BOX_PUBLIC_KEY`

3. save the `B key` in a very, very secure place NOT on the server.

4. submissions will now be saved encrypted, with NO way to encrypt them without the `B key`.

5. You can use the config below to add exceptions.

## config

You can customise the encryption like this:

```yml
Sunnysideup\UserFormSealedEncryption\Extensions\SubmittedFormFieldExtension:
  no_encryption_at_all: true
  fields_to_encrypt:
    - FieldNameA
  fields_not_to_encrypt:
    - FieldNameB
  field_types_to_encrypt:
    FooBar\ClassA
  field_types_not_to_encrypt:
    FooBar\ClassB
```

## to encrypt

To decrypt you can use the `decryptor/index.html` file included in this module.
