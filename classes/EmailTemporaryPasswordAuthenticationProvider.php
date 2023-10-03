<?php

namespace EmailLogin;

use MediaWiki\Auth\AuthenticationRequest;
use MediaWiki\Auth\AuthenticationResponse;
use MediaWiki\Auth\TemporaryPasswordPrimaryAuthenticationProvider;
use MediaWiki\Auth\PasswordAuthenticationRequest;

class EmailTemporaryPasswordAuthenticationProvider extends TemporaryPasswordPrimaryAuthenticationProvider
{
    public function beginPrimaryAuthentication(array $reqs)
    {
        $req = AuthenticationRequest::getRequestByClass($reqs, PasswordAuthenticationRequest::class);

        $dbr = wfGetDB(DB_MASTER);
        // as EmailPasswordAuthenticationProvider is declared first,
        // EmailPasswordAuthenticationProvider class has been called,
        // and username is already changed from mail to username
        $rows = $dbr->select(
            'user',
            ['user_email', 'user_name'],
            ['user_name' => $req->username],
            __METHOD__
        );

        foreach ($rows as $row) {
            $req->username = $row->user_name;

            $result = parent::beginPrimaryAuthentication([$req]);
            if ($result->status == 'PASS') {
                return $result;
            }
        }

        return AuthenticationResponse::newAbstain();
    }
}
