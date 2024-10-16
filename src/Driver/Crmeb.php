<?php

namespace Iyuu\ScanLogin\Driver;

use app\dao\system\admin\SystemAdminDao;
use app\services\system\admin\SystemAdminServices;
use app\services\system\SystemMenusServices;
use crmeb\exceptions\AdminException;
use ErrorException;
use Iyuu\ScanLogin\Contracts\Driver;
use Iyuu\ScanLogin\RsaCrypt;
use Iyuu\ScanLogin\WechatAccountRocket;
use think\db\exception\DataNotFoundException;
use think\db\exception\DbException;
use think\db\exception\ModelNotFoundException;
use think\facade\Config;
use think\facade\Event;
use think\Request;
use think\Response;
use Throwable;

/**
 * 单商户标准版CRMEB-BZ v5.4.0(20240708)
 */
class Crmeb implements Driver
{
    /**
     * @var SystemAdminDao
     */
    protected SystemAdminDao $dao;
    /**
     * @var SystemAdminServices
     */
    protected SystemAdminServices $service;

    /**
     * 构造函数
     * @param SystemAdminDao $dao
     * @param SystemAdminServices $service
     */
    public function __construct(SystemAdminDao $dao, SystemAdminServices $service)
    {
        $this->dao = $dao;
        $this->service = $service;
    }

    /**
     * @param Request|\app\Request|null $request
     * @return Response
     */
    public function handle(Request $request = null): Response
    {
        /** @var SystemAdminServices $service */
        $service = app()->make(SystemAdminServices::class);
        [$payload, $signature, $key] = $request->postMore(['payload/s', 'signature/s', 'key/s'], true);
        if (empty($payload)) {
            return app('json')->fail('payload is empty');
        }
        if (empty($signature)) {
            return app('json')->fail('signature is empty');
        }
        if (empty($key)) {
            return app('json')->fail('key is empty');
        }

        try {
            $rsaCrypt = self::makeRsaCrypt($key);
            $data = $rsaCrypt->decrypt($payload, $signature);
            $rocket = new WechatAccountRocket($data);

            $list = Config::get('iyuu.scan_login') ?: [];
            if (empty($list)) {
                return app('json')->fail(strtoupper('iyuu.scan_login') . ' list is empty');
            }

            foreach ($list as $account => $tokens) {
                foreach ($tokens as $token) {
                    if (password_verify($token, $rocket->token_password_hash)) {
                        $result = $this->login($account);
                        if (!$result) {
                            return app('json')->fail(400140);
                        }
                        return app('json')->success($result);
                    }
                }
            }

            return app('json')->fail('登录失败：token哈希与登录方不一致');
        } catch (Throwable $throwable) {
            return app('json')->fail($throwable->getMessage());
        }
    }

    /**
     * 以下登录代码从 \app\services\system\admin\SystemAdminServices::login 复制过来的
     * @param string $account
     * @return array|bool
     * @throws DataNotFoundException
     * @throws DbException
     * @throws ModelNotFoundException
     */
    private function login(string $account)
    {
        $adminInfo = $this->dao->accountByAdmin($account);
        if (empty($adminInfo)) {
            throw new AdminException(400140);
        }

        if (!$adminInfo->status) {
            throw new AdminException(400595);
        }
        $adminInfo->last_time = time();
        $adminInfo->last_ip = app('request')->ip();
        $adminInfo->login_count++;
        $adminInfo->save();

        $tokenInfo = $this->service->createToken($adminInfo->id, 'admin', $adminInfo->pwd);
        /** @var SystemMenusServices $services */
        $services = app()->make(SystemMenusServices::class);
        [$menus, $uniqueAuth] = $services->getMenusList($adminInfo->roles, (int)$adminInfo['level']);
        $remind = Config::get('app.console_remind', false);
        if ($remind) {
            [$queue, $timer] = Event::until('AdminLoginListener', ['']);
        }

        //自定义事件-管理员登录
        event('CustomEventListener', ['admin_login', [
            'id' => $adminInfo->getData('id'),
            'account' => $adminInfo->getData('account'),
            'head_pic' => get_file_link($adminInfo->getData('head_pic')),
            'level' => $adminInfo->getData('level'),
            'real_name' => $adminInfo->getData('real_name'),
            'login_time' => date('Y-m-d H:i:s'),
        ]]);

        return [
            'token' => $tokenInfo['token'],
            'expires_time' => $tokenInfo['params']['exp'],
            'menus' => $menus,
            'unique_auth' => $uniqueAuth,
            'user_info' => [
                'id' => $adminInfo->getData('id'),
                'account' => $adminInfo->getData('account'),
                'head_pic' => get_file_link($adminInfo->getData('head_pic')),
                'level' => $adminInfo->getData('level'),
                'real_name' => $adminInfo->getData('real_name'),
            ],
            'logo' => sys_config('site_logo'),
            'logo_square' => sys_config('site_logo_square'),
            'version' => get_crmeb_version(),
            'newOrderAudioLink' => get_file_link(sys_config('new_order_audio_link', '')),
            'queue' => $queue ?? true,
            'timer' => $timer ?? true,
            'site_name' => sys_config('site_name'),
            'site_func' => sys_config('model_checkbox', ['seckill', 'bargain', 'combination']),
        ];
    }

    /**
     * 创建RsaCrypt对象实例
     * - 非对称私钥加签验签；对称密钥加密解密
     * @param string $key
     * @return RsaCrypt
     * @throws ErrorException
     */
    public static function makeRsaCrypt(string $key): RsaCrypt
    {
        return new RsaCrypt(
            dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'pem' . DIRECTORY_SEPARATOR . 'rsa_private.key',
            dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'pem' . DIRECTORY_SEPARATOR . 'rsa_public.key',
            $key
        );
    }
}
