<?php

error_reporting(E_ALL);
ini_set('display_errors',1);


// ===========================
// SECRET KEY SERVER
// ===========================

$SECRET_KEY = "Kunci_Super_Aman_Univ_Muh_PTK_2026";



// ===========================
// BASE64 URL ENCODE
// ===========================

function base64url_encode($data)
{

    return rtrim(
        strtr(
            base64_encode($data),
            '+/',
            '-_'
        ),
        '='
    );

}



// ===========================
// BASE64 URL DECODE
// ===========================

function base64url_decode($data)
{

    $data = strtr(
        $data,
        '-_',
        '+/'
    );


    $padding = strlen($data)%4;


    if($padding)
    {

        $data .= str_repeat(
            '=',
            4-$padding
        );

    }


    return base64_decode($data);

}



// ===========================
// CREATE JWT
// ===========================

function create_jwt($payload_data,$secret)
{


    // HEADER

    $header = json_encode([
        "typ"=>"JWT",
        "alg"=>"HS256"
    ]);



    // PAYLOAD

    $payload=json_encode(
        $payload_data
    );



    $headerEncode =
    base64url_encode($header);


    $payloadEncode =
    base64url_encode($payload);




    // SIGNATURE

    $signature = hash_hmac(
        "sha256",
        $headerEncode.".".$payloadEncode,
        $secret,
        true
    );



    $signatureEncode =
    base64url_encode($signature);




    return

    $headerEncode.".".
    $payloadEncode.".".
    $signatureEncode;


}



// ===========================
// VERIFY JWT
// ===========================

function verify_jwt($jwt,$secret)
{


    $parts =
    explode(".",$jwt);



    if(count($parts)!=3)
    {

        return [

            "valid"=>false,

            "pesan"=>"Format Token Salah"

        ];

    }



    $header=$parts[0];

    $payload=$parts[1];

    $signature=$parts[2];





    // HITUNG ULANG SIGNATURE

    $newSignature = hash_hmac(
        "sha256",
        $header.".".$payload,
        $secret,
        true
    );



    $newSignature =
    base64url_encode($newSignature);




    // CEK TAMPERING

    if(!hash_equals(
        $newSignature,
        $signature
    ))
    {

        return [

            "valid"=>false,

            "pesan"=>"Token Dimodifikasi / Palsu (Signature Invalid)"

        ];

    }




    $data=json_decode(

        base64url_decode($payload),

        true

    );




    // CEK EXPIRED

    if(isset($data['exp']))
    {

        if(time()>$data['exp'])
        {

            return [

                "valid"=>false,

                "pesan"=>"Token Expired"

            ];

        }

    }



    return [

        "valid"=>true,

        "pesan"=>"Token Sah",

        "data"=>$data

    ];

}




// ===========================
// CONTROLLER
// ===========================


$token="";

$hasil="";



if($_SERVER["REQUEST_METHOD"]=="POST")
{


    // GENERATE TOKEN


    if(isset($_POST['generate']))
    {


        $payload=[


            "iss"=>"web_universitas",

            "user_id"=>$_POST['userid'],

            "role"=>$_POST['role'],

            "exp"=>time()+3600


        ];



        $token =
        create_jwt(
            $payload,
            $SECRET_KEY
        );


    }





    // VERIFY TOKEN


    if(isset($_POST['verify']))
    {


        $cek =
        verify_jwt(
            $_POST['token'],
            $SECRET_KEY
        );



        if($cek['valid'])
        {

            $hasil=

            "

            <div class='success'>

            ✅ ".$cek['pesan']."


            <pre>"
            .
            json_encode(
                $cek['data'],
                JSON_PRETTY_PRINT
            )
            .
            "</pre>


            </div>

            ";

        }

        else
        {


            $hasil=

            "

            <div class='error'>

            ❌ ".$cek['pesan']."

            </div>

            ";


        }


    }



}

?>



<!DOCTYPE html>

<html>


<head>


<title>

JWT Engine API

</title>



<link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;500;600;700&display=swap" rel="stylesheet">



<style>


*{

box-sizing:border-box;

}



body{


font-family:'Montserrat',sans-serif;

background:

linear-gradient(
135deg,
#eef2ff,
#f8fafc
);


padding:40px;


color:#1e293b;


}



.container{


max-width:850px;

margin:auto;


}




.header{


background:white;

padding:35px;

border-radius:20px;

margin-bottom:25px;


box-shadow:

0 10px 30px rgba(0,0,0,.08);


}



.header h1{


margin:0;

font-size:32px;

color:#312e81;


}



.header p{


color:#64748b;


}



.badge{


display:inline-block;

background:#ede9fe;

color:#5b21b6;

padding:8px 15px;

border-radius:20px;

font-size:12px;

font-weight:600;


}




.box{


background:white;

padding:35px;

border-radius:20px;

margin-bottom:25px;


box-shadow:

0 10px 25px rgba(0,0,0,.08);


}



.box h2{


color:#3730a3;


}



input,textarea{


width:100%;

padding:14px;

margin-top:10px;

margin-bottom:15px;


border-radius:12px;

border:1px solid #cbd5e1;


font-family:'Montserrat';


}



textarea{


resize:none;

background:#f8fafc;


}




button{


background:

linear-gradient(
135deg,
#4f46e5,
#7c3aed
);


color:white;

border:none;

padding:14px 25px;


border-radius:12px;

font-weight:600;

cursor:pointer;


}



button:hover{


opacity:.9;


}




.success{


background:#dcfce7;

color:#166534;

padding:15px;

border-radius:12px;


}



.error{


background:#fee2e2;

color:#991b1b;

padding:15px;

border-radius:12px;


}



pre{


background:white;

padding:10px;

border-radius:8px;


}



</style>



</head>



<body>


<div class="container">



<div class="header">


<h1>

JWT Engine API Demo

</h1>


<p>

Simulasi Pembuatan dan Verifikasi JSON Web Token menggunakan HMAC SHA256

</p>


<span class="badge">

KRIPTOGRAFI • JWT • API SECURITY

</span>


</div>





<div class="box">


<h2>

1. Generate Token Sah

</h2>



<form method="POST">


<label>
User ID
</label>


<input

type="text"

name="userid"

value="U001"


>


<label>

Role

</label>


<input

type="text"

name="role"

value="user"


>



<button name="generate">

Generate JWT

</button>



</form>



<br>


<textarea rows="5" readonly>

<?=htmlspecialchars($token)?>

</textarea>



</div>






<div class="box">


<h2>

2. Verifikasi Endpoint API

</h2>



<form method="POST">


<textarea

name="token"

rows="6"

placeholder="Paste JWT hasil jwt.io disini"

></textarea>




<button name="verify">

Cek Validitas

</button>



</form>



<br>


<?=$hasil?>



</div>



</div>



</body>


</html>