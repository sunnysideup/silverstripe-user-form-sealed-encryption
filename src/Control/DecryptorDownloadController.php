<?php

namespace Sunnysideup\UserFormSealedEncryption\Control;

use SilverStripe\Control\Controller;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Core\Path;
use SilverStripe\Security\Permission;
use SilverStripe\Security\Security;

/**
 * CMS-only download of the self-contained decryptor page.
 * The page contains no secrets; the login requirement just keeps it off the public site.
 */
class DecryptorDownloadController extends Controller
{
    private static string $url_segment = 'admin/sealed-box-decryptor';

    private static array $allowed_actions = ['index'];

    public function Link($action = null)
    {
        return Controller::join_links(Director::baseURL(), $this->config()->get('url_segment'), $action);
    }

    public function index(HTTPRequest $request): HTTPResponse
    {
        if (!Permission::check('CMS_ACCESS_LeftAndMain')) {
            return Security::permissionFailure($this);
        }
        $file = Path::join(dirname(__DIR__, 2), 'decryptor', 'index.html');
        if (!is_file($file) || filesize($file) === 0) {
            return $this->httpError(404, 'Decryptor not built.');
        }
        $response = HTTPResponse::create(file_get_contents($file));
        $response->addHeader('Content-Type', 'text/html; charset=utf-8');
        $response->addHeader('Content-Disposition', 'attachment; filename="sealed-box-decryptor.html"');
        $response->addHeader('Cache-Control', 'no-store');
        return $response;
    }
}
