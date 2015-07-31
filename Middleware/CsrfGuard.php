<?php
/**
 * CSRF Guard
 *
 * Use this middleware with your Slim Framework application
 * to protect you from CSRF attacks.
 *
 * USAGE
 *
 * $app = new \Slim\Slim();
 * $app->add(new \Slim\Extras\Middleware\CsrfGuard());
 *
 */
namespace Slim\Extras\Middleware;

class CsrfGuard extends \Slim\Middleware
{
    /**
     * CSRF token key name.
     *
     * @var string
     */
    protected $key;

    protected $excluded = array();

    /**
     * Constructor.
     *
     * @param string    $key        The CSRF token key name.
     * @return void
     */
    public function __construct($key = 'csrf_token')
    {
        if (! is_string($key) || empty($key) || preg_match('/[^a-zA-Z0-9\-\_]/', $key)) {
            throw new \OutOfBoundsException('Invalid CSRF token key "' . $key . '"');
        }

        $this->key = $key;
        $this->excluded = [];
    }


    public function addExcludedRoutes($r) {
        if (is_array($r) && !empty($r)) {
            foreach($r as $k=>$R) {
                $r[$k] = $this->app->router()->urlFor($R); // Replace route-name by route-url
            }   
            $this->excluded = array_merge($this->excluded, $r);
        }
        else if (is_string($r) && !empty($r) ) {
            $this->excluded[] = $this->app->router()->urlFor($r);
        }   
        else
            throw new \Exception('addExcludedRoutes excepts an array of strings, or a string as parameters');
    }


    /**
     * Call middleware.
     *
     * @return void
     */
    public function call() 
    {
        // Attach as hook.
        $this->app->hook('slim.before', array($this, 'check'));

        // Call next middleware.
        $this->next->call();
    }

    /**
     * Check CSRF token is valid.
     * Note: Also checks POST data to see if a Moneris RVAR CSRF token exists.
     *
     * @return void
     */
    public function check() {
        // Check sessions are enabled.
        if (session_id() === '') {
            throw new \Exception('Sessions are required to use the CSRF Guard middleware.');
        }

        if (! isset($_SESSION[$this->key])) {
            $_SESSION[$this->key] = sha1(serialize($_SERVER) . rand(0, 0xffffffff));
        }

        $token = $_SESSION[$this->key];
        
        // Validate the CSRF token (if check is needed)    
        //var_dump($this->app->router()->urlFor($this->excluded[0]) );
        //die();
        $should_check = (!empty($this->excluded) && !in_array($this->app->request()->getResourceUri(), $this->excluded));
        $should_check_cause_method = in_array($this->app->request()->getMethod(), array('POST', 'PUT', 'DELETE'));

        if ($should_check && $should_check_cause_method) {
            $userToken = $this->app->request()->post($this->key);
            if ($token !== $userToken) {
                $this->app->halt(400, 'Invalid or missing CSRF token.');
            }
        }

        // Assign CSRF token key and value to view.
        $this->app->view()->appendData(array(
            'csrf_key'      => $this->key,
            'csrf_token'    => $token,
        ));
    }
}
