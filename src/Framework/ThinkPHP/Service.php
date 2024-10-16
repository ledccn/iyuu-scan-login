<?php

namespace Iyuu\ScanLogin\Framework\ThinkPHP;

use Iyuu\ScanLogin\Contracts\Driver;
use Iyuu\ScanLogin\Driver\Crmeb;
use think\Request;
use think\Response;
use think\Route;

/**
 * 系统服务
 */
class Service extends \think\Service
{
    /**
     * 登录驱动的命名空间
     */
    const NAMESPACE_IYUU_SCAN_LOGIN_DRIVER = 'iyuu.scan-login.driver.';

    /**
     * 绑定容器对象
     * @var array
     */
    public array $bind = [
        self::NAMESPACE_IYUU_SCAN_LOGIN_DRIVER . 'crmeb' => Crmeb::class,
    ];

    /**
     * 服务注册
     * @description 通常用于注册系统服务，也就是将服务绑定到容器中。
     * @return void
     */
    public function register(): void
    {
    }

    /**
     * 服务启动
     * @description 在所有的系统服务注册完成之后调用，用于定义启动某个系统服务之前需要做的操作。
     * @param Route $route
     * @return void
     */
    public function boot(Route $route): void
    {
        // 注册路由
        $route->any('/iyuu/scan/login/:driver', function (Request $request, $driver): Response {
            if ($request->method(true) === 'OPTIONS') {
                $header = [
                    'Access-Control-Allow-Origin' => '*',
                    'Access-Control-Allow-Headers' => '*',
                    'Access-Control-Allow-Methods' => '*',
                    'Access-Control-Max-Age' => '1728000',
                    'Access-Control-Allow-Credentials' => 'true'
                ];
                return Response::create('ok')->code(200)->header($header);
            }

            // 校验驱动参数
            if (!ctype_alnum($driver)) {
                return json(['code' => 400, 'msg' => '登录驱动名称只能为字母数字']);
            }

            $app = $this->app;
            $abstract = $this->getAlias($driver);
            if (!$app->bound($abstract)) {
                return json(['code' => 404, 'msg' => '暂未支持的登录驱动名称']);
            }

            $instance = $app->make($abstract);
            if ($instance instanceof Driver) {
                return $app->invokeMethod([$instance, 'handle']);
            }
            return json(['code' => 500, 'msg' => '登录驱动未实现接口，请联系开发者']);
        });

        // 注册命令
        $this->commands([
            Command::class,
        ]);
    }

    /**
     * 获取完整的容器标识
     * @param string $driver 驱动名称
     * @return string
     */
    private function getAlias(string $driver): string
    {
        return self::NAMESPACE_IYUU_SCAN_LOGIN_DRIVER . $driver;
    }
}
