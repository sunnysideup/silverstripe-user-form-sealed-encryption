# tl;dr

1. generate the `A` and `B` keys, locally, from the comand line.

2. save the `A key` on the server, in the `.env` file: `SS_SEALED_BOX_PUBLIC_KEY`

3. save the `B key` in a very, very secure place NOT on the server.

4. submissions will be saved encrypted, with NO way to encrypt them without the B key.

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

Download database.
Write a manual script to decrypt data with `B key`.
