<?php

namespace Sunnysideup\UserFormSealedEncryption\Extensions;

use SilverStripe\Core\Environment;
use SilverStripe\Core\Extension;
use SilverStripe\Forms\FormField;
use SilverStripe\UserForms\Model\EditableFormField;
use SilverStripe\UserForms\Model\Submission\SubmittedFormField;
use Sunnysideup\UserFormSealedEncryption\Api\SealedBox;

class SubmittedFormFieldExtension extends Extension
{
    private static bool $no_encryption_at_all = false;

    private static array $fields_not_to_encrypt = [];

    private static array $fields_to_encrypt = [];

    private static array $field_types_to_encrypt = [];

    private static array $field_types_not_to_encrypt = [];

    /**
     * If true, the value is encrypted only for the database write.
     * The in-memory value stays plain text, so emails sent afterwards
     * contain readable content. Plain text is never stored.
     */
    private static bool $encrypt_after_email = false;

    private ?string $plainValueToRestore = null;

    private bool $pendingEncryption = false;

    public function onPopulationFromField(EditableFormField $field)
    {
        $owner = $this->getOwner();
        $publicKeyB64 = Environment::getEnv('SS_SEALED_BOX_PUBLIC_KEY');
        if (!$publicKeyB64) {
            return;
        }
        if ($owner->config()->get('no_encryption_at_all')) {
            return;
        }
        $fieldName = $field->Name;
        if (in_array($fieldName, $owner->config()->get('fields_not_to_encrypt'))) {
            return;
        }
        if (!empty($owner->config()->get('fields_to_encrypt')) && !in_array($fieldName, $owner->config()->get('fields_to_encrypt'))) {
            return;
        }
        /**
         * @var SubmittedFormField $submittedFormField
         */
        $submittedFormField = $this->getOwner();
        $fieldClass = get_class($submittedFormField);
        if (in_array($fieldClass, $owner->config()->get('field_types_not_to_encrypt'))) {
            return;
        }
        if (!empty($owner->config()->get('field_types_to_encrypt')) && !in_array($fieldClass, $owner->config()->get('field_types_to_encrypt'))) {
            return;
        }
        if ($owner->config()->get('encrypt_after_email')) {
            // encrypted in onBeforeWrite, restored in onAfterWrite
            $this->pendingEncryption = true;
            return;
        }
        $value = (string) $submittedFormField->Value;
        $submittedFormField->Value = SealedBox::encrypt($value, $publicKeyB64);
    }

    public function onBeforeWrite()
    {
        if (!$this->pendingEncryption) {
            return;
        }
        $publicKeyB64 = Environment::getEnv('SS_SEALED_BOX_PUBLIC_KEY');
        if (!$publicKeyB64) {
            return;
        }
        $owner = $this->getOwner();
        $this->plainValueToRestore = (string) $owner->Value;
        $owner->Value = SealedBox::encrypt($this->plainValueToRestore, $publicKeyB64);
    }

    public function onAfterWrite()
    {
        if ($this->plainValueToRestore !== null) {
            $this->getOwner()->Value = $this->plainValueToRestore;
            $this->plainValueToRestore = null;
        }
        $this->pendingEncryption = false;
    }
}
