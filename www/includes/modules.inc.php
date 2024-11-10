<?php

 #Modules and how they can be accessed.

 #access:
 #auth = need to be logged-in to see it
 #hidden_on_login = only visible when not logged in
 #admin = need to be logged in as an admin to see it
 #always = always visible

 $MODULES = array(
                    'log_in'          => 'hidden_on_login',
                    'change_password' => 'auth',
                    'account_manager' => 'admin',
                  );

if ($ACCOUNT_REQUESTS_ENABLED == TRUE) {
  if ($ACCOUNT_REQUESTS_ALWAYS_SHOW == TRUE) {
    $MODULES['request_account'] = 'always';
  } else {
    $MODULES['request_account'] = 'hidden_on_login';
  }
}
if (!$REMOTE_HTTP_HEADERS_LOGIN) {
  $MODULES['log_out'] = 'auth';
}

?>
