<?php

namespace Sunnysideup\UserFormSealedEncryption\Extensions;

use SilverStripe\Core\Environment;
use SilverStripe\Core\Extension;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\LiteralField;
use Sunnysideup\UserFormSealedEncryption\Control\DecryptorDownloadController;

/**
 * Adds a decryptor download link above the submissions in the CMS.
 */
class UserFormCmsExtension extends Extension
{
    public function updateCMSFields(FieldList $fields)
    {
        if (!Environment::getEnv('SS_SEALED_BOX_PUBLIC_KEY') || !$fields->findTab('Root.Submissions')) {
            return;
        }
        $url = DecryptorDownloadController::singleton()->Link();
        $fields->addFieldToTab(
            'Root.Submissions',
            LiteralField::create(
                'SealedBoxDecryptorLink',
                '<p class="message notice">Submissions are encrypted in such a way that only someone with the private key can read them.
                The private key is not uploaded or stored anywhere on the site. '
                . '<br /><a href="' . htmlspecialchars($url) . '" download>Download the decryptor</a>, '
                . 'open it on your computer, and paste in your private key and the exported data (e.g. CSV) to read it. '
                . 'Nothing will be uploaded in this process.</p>'
            ),
            'Submissions'
        );
    }
}
