<?php

namespace EmailLogin;

use MediaWiki\Auth\AuthenticationRequest;
use MediaWiki\Auth\AuthenticationResponse;
use MediaWiki\Auth\LocalPasswordPrimaryAuthenticationProvider;
use MediaWiki\Auth\PasswordAuthenticationRequest;

class EmailPasswordAuthenticationProvider extends LocalPasswordPrimaryAuthenticationProvider {

    public function beginPrimaryAuthentication(array $reqs) {
        $req = AuthenticationRequest::getRequestByClass($reqs, PasswordAuthenticationRequest::class);

        $dbr = wfGetDB( DB_REPLICA );
        $row = $dbr->selectRow(
            'user',
            ['user_email', 'user_name'],
            ['user_email' => $req->username],
            __METHOD__
        );
        if (!$row) {
            return AuthenticationResponse::newAbstain();
        }
        $req->username = $row->user_name;
        return parent::beginPrimaryAuthentication([$req]);
    }

}
