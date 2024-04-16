//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : root_certificates.h

#ifndef BOOST_BEAST_EXAMPLE_COMMON_ROOT_CERTIFICATES_HPP
#define BOOST_BEAST_EXAMPLE_COMMON_ROOT_CERTIFICATES_HPP

#include <boost/asio/ssl.hpp>
#include <string>

namespace ssl = boost::asio::ssl;

namespace detail{

inline
void 
load_root_certificates(ssl::context& ctx, boost::system::error_code& ec)
{
    /* begin cert here*/
    std::string const cert = 
    "-----BEGIN CERTIFICATE-----\n"
	"MIIEETCCAnkCFCrLHwquLglAKKLidfpJuwxKPvoMMA0GCSqGSIb3DQEBCwUAMEUx\n"
	"SfG9PQqfWo7DxNJYosbYL1h+GYM8R+2IrZWzMYemUJxTt78PAw==\n"
	"-----END CERTIFICATE-----\n"
    ;

    ctx.add_certificate_authority(
        boost::asio::buffer(cert.data(), cert.size()), ec);
    if (ec){
        printf("\n error \n");
		return ;
    }
}

}

//load the root certificates into an ssl::context
inline 
void 
load_root_certificates(ssl::context& ctx, boost::system::error_code& ec)
{
    detail::load_root_certificates(ctx, ec);
}

inline 
void
load_root_certificates(ssl::context& ctx){
    boost::system::error_code ec;
    detail::load_root_certificates(ctx, ec);
    if (ec){
        throw boost::system::system_error{ec};
    }
}

#endif





