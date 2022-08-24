<?php declare(strict_types=1);

namespace App\Domains\User\Action;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use App\Exceptions\AuthenticationException;
use App\Domains\User\Model\User as Model;

class AuthCredentials extends ActionAbstract
{
    /**
     * @return \App\Domains\User\Model\User
     */
    public function handle(): Model
    {
        $this->check();
        $this->auth();
        $this->login();
        $this->success();
        $this->session();

        return $this->row;
    }

    /**
     * @return void
     */
    protected function checkIp(): void
    {
        $this->factory('IpLock')->action()->check();
    }

    /**
     * @return void
     */
    protected function row(): void
    {
        $this->row = Model::byEmail($this->data['email'])->enabled()->firstOr(fn () => $this->fail());
    }

    /**
     * @return void
     */
    protected function check(): void
    {
        $this->checkIp();
    }


    /**
     * @throws \App\Exceptions\AuthenticationException
     *
     * @return void
     */
    protected function fail(): void
    {
        $this->factory('UserSession')->action(['auth' => $this->data['email']])->fail();

        throw new AuthenticationException(__('user-auth-credentials.error.auth-fail'));
    }

    /**
     * @return void
     */
    protected function login(): void
    {
        Auth::login($this->row, true);
    }

    /**
     * @return void
     */
    protected function auth(): void
    {
        $credentials = [
            'mail' => $this->data['email'],
            'password' => $this->data['password'],
            'fallback' => [
                'email' => $this->data['email'],
                'password' => $this->data['password'],
            ],
        ];


        if (Auth::attempt($credentials)) {
           $this->row();
        } else {
            $this->fail();
        }

    }

    /**
     * @return void
     */
    protected function success(): void
    {
        $this->factory('UserSession')->action(['auth' => $this->data['email']])->success($this->row);
    }

    /**
     * @return void
     */
    protected function session(): void
    {
        $this->request->session()->forget('tfa:id');
    }
}
