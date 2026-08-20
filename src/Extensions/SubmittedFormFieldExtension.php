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
        $value = (string) $submittedFormField->Value;
        $submittedFormField->Value = SealedBox::encrypt($value, $publicKeyB64);
    }
}
