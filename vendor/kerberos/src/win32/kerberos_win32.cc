#include <memory>

#include "../kerberos.h"
#include "../kerberos_worker.h"

namespace node_kerberos {

using namespace Napi;

static Napi::Object native_error(Napi::Env env, const sspi_result& result) {
    auto error = Error::New(env, result.message).Value();
    error.Set("sspiCode", Number::New(env, result.security_status));
    return error;
}

inline std::wstring ToWStringWithNonStringAsEmpty(Value value) {
    static_assert(sizeof(std::wstring::value_type) == sizeof(std::u16string::value_type),
        "wstring and u16string have the same value type on Windows");
    if (!value.IsString()) {
        return std::wstring();
    }
    std::u16string u16 = value.As<String>();
    return std::wstring(u16.begin(), u16.end());
}

#define GSS_MECH_OID_KRB5 9
#define GSS_MECH_OID_SPNEGO 6
#define GSS_MECH_OID_KRB5_STR L"Kerberos"
#define GSS_MECH_OID_SPNEGO_STR L"Negotiate"

#define GSS_C_MUTUAL_FLAG 2
#define GSS_C_REPLAY_FLAG 4
#define GSS_C_SEQUENCE_FLAG 8

/// KerberosClient
void KerberosClient::Step(const CallbackInfo& info) {
    auto state = this->state();
    std::string challenge = info[0].ToString();
    Function callback = info[1].As<Function>();

    KerberosWorker::Run(callback, "kerberos:ClientStep", [=](KerberosWorker::SetOnFinishedHandler onFinished) {
        sspi_result result =
            auth_sspi_client_step(state.get(), (SEC_CHAR*)challenge.c_str());

        return onFinished([=](KerberosWorker* worker) {
            Napi::Env env = worker->Env();
            if (result.code == AUTH_GSS_ERROR) {
                worker->Call(std::initializer_list<napi_value>
                    { native_error(env, result), env.Null() });
                return;
            }

            Napi::Value response = env.Null();
            if (state->response != nullptr) {
                response = String::New(env, state->response);
            }

            worker->Call(std::initializer_list<napi_value>
                { env.Null(), response });
        });
    });
}

void KerberosClient::UnwrapData(const CallbackInfo& info) {
    auto state = this->state();
    std::string challenge = info[0].ToString();
    Function callback = info[1].As<Function>();

    KerberosWorker::Run(callback, "kerberos:ClientUnwrap", [=](KerberosWorker::SetOnFinishedHandler onFinished) {
        sspi_result result =
            auth_sspi_client_unwrap(state.get(), (SEC_CHAR*)challenge.c_str());

        return onFinished([=](KerberosWorker* worker) {
            Napi::Env env = worker->Env();
            if (result.code == AUTH_GSS_ERROR) {
                worker->Call(std::initializer_list<napi_value>
                    { native_error(env, result), env.Null() });
                return;
            }

            worker->Call(std::initializer_list<napi_value>
                { env.Null(), String::New(env, state->response) });
        });
    });
}

static bool isStringTooLong(const std::string& str) {
    return str.length() >= ULONG_MAX;
}

static bool isWStringTooLong(const std::wstring& str) {
    return str.length() >= ULONG_MAX;
}

void KerberosClient::UnwrapDataWithResult(const CallbackInfo& info) {
    auto state = this->state();
    std::string challenge = info[0].ToString();
    Function callback = info[1].As<Function>();

    KerberosWorker::Run(callback, "kerberos:ClientUnwrapWithResult", [=](KerberosWorker::SetOnFinishedHandler onFinished) {
        sspi_result result = auth_sspi_client_unwrap(state.get(), (SEC_CHAR*)challenge.c_str());

        return onFinished([=](KerberosWorker* worker) {
            Napi::Env env = worker->Env();
            if (result.code == AUTH_GSS_ERROR) {
                worker->Call(std::initializer_list<napi_value>
                    { native_error(env, result), env.Null() });
                return;
            }

            Object unwrapped = Object::New(env);
            unwrapped.Set("response", String::New(env, state->response ? state->response : ""));
            unwrapped.Set("confidential", Boolean::New(env, result.confidentiality));
            unwrapped.Set("integrity", Boolean::New(env, result.integrity));
            worker->Call(std::initializer_list<napi_value>{ env.Null(), unwrapped });
        });
    });
}

void KerberosClient::WrapSizeLimit(const CallbackInfo& info) {
    auto state = this->state();
    ULONG max_output_size = info[0].As<Number>().Uint32Value();
    Function callback = info[2].As<Function>();

    KerberosWorker::Run(callback, "kerberos:ClientWrapSizeLimit", [=](KerberosWorker::SetOnFinishedHandler onFinished) {
        ULONG max_input_size = 0;
        sspi_result result = auth_sspi_client_wrap_size_limit(state.get(), max_output_size, &max_input_size);
        return onFinished([=](KerberosWorker* worker) {
            Napi::Env env = worker->Env();
            if (result.code == AUTH_GSS_ERROR) {
                worker->Call(std::initializer_list<napi_value>{ native_error(env, result), env.Null() });
                return;
            }
            worker->Call(std::initializer_list<napi_value>{ env.Null(), Number::New(env, max_input_size) });
        });
    });
}

void KerberosClient::WrapData(const CallbackInfo& info) {
    WrapDataInternal(info, false);
}

void KerberosClient::WrapDataWithResult(const CallbackInfo& info) {
    WrapDataInternal(info, true);
}

void KerberosClient::WrapDataInternal(const CallbackInfo& info, bool detailed) {
    auto state = this->state();
    std::string challenge = info[0].ToString();
    Object options = info[1].ToObject();
    Function callback = info[2].As<Function>();
    std::string user = ToStringWithNonStringAsEmpty(options["user"]);
    int protect = ParseWrapOptionsProtect(options);

    if (isStringTooLong(user)) {
        throw Error::New(info.Env(), "User name is too long");
    }

    KerberosWorker::Run(callback, "kerberos:ClientWrap", [=](KerberosWorker::SetOnFinishedHandler onFinished) {
        sspi_result result = detailed
            ? auth_sspi_client_wrap_data(
                state.get(), (SEC_CHAR*)challenge.c_str(), protect)
            : auth_sspi_client_wrap_selection(
                state.get(), (SEC_CHAR*)challenge.c_str(), (SEC_CHAR*)user.c_str(),
                (ULONG)user.length(), protect);

        return onFinished([=](KerberosWorker* worker) {
            Napi::Env env = worker->Env();

            if (result.code == AUTH_GSS_ERROR) {
                worker->Call(std::initializer_list<napi_value>
                    { native_error(env, result), env.Null() });
                return;
            }

            if (detailed) {
                Object wrapped = Object::New(env);
                wrapped.Set("response", String::New(env, state->response));
                wrapped.Set("confidential", Boolean::New(env, result.confidentiality));
                wrapped.Set("integrity", Boolean::New(env, result.integrity));
                worker->Call(std::initializer_list<napi_value>{ env.Null(), wrapped });
            } else {
                worker->Call(std::initializer_list<napi_value>
                    { env.Null(), String::New(env, state->response) });
            }
        });
    });
}

/// KerberosServer
void KerberosServer::Step(const CallbackInfo& info) {
    throw Error::New(info.Env(), "`KerberosServer::Step` is not implemented yet for windows");
}

/// Global Methods
void InitializeClient(const CallbackInfo& info) {
    std::wstring service = ToWStringWithNonStringAsEmpty(info[0]);
    Object options = info[1].ToObject();
    Function callback = info[2].As<Function>();

    std::wstring user = ToWStringWithNonStringAsEmpty(options["user"]);
    std::wstring domain = ToWStringWithNonStringAsEmpty(options["domain"]);
    std::wstring password = ToWStringWithNonStringAsEmpty(options["password"]);
    const ChannelBindingInput channel_bindings = read_channel_binding_input(options);

    if (isWStringTooLong(user)) {
        throw Error::New(info.Env(), "User name is too long");
    }
    if (isWStringTooLong(domain)) {
        throw Error::New(info.Env(), "Domain is too long");
    }
    if (isWStringTooLong(password)) {
        throw Error::New(info.Env(), "Password is too long");
    }

    Value flags_v = options["flags"];
    ULONG gss_flags = flags_v.IsNumber() ? flags_v.As<Number>().Uint32Value() : GSS_C_MUTUAL_FLAG|GSS_C_SEQUENCE_FLAG;
    Value mech_oid_v = options["mechOID"];
    uint32_t mech_oid_int = mech_oid_v.IsNumber() ? mech_oid_v.As<Number>().Uint32Value() : 0;
    std::wstring mech_oid = GSS_MECH_OID_KRB5_STR;
    if (mech_oid_int == GSS_MECH_OID_SPNEGO) {
        mech_oid = GSS_MECH_OID_SPNEGO_STR;
    }

    KerberosWorker::Run(callback, "kerberos:InitializeClient", [=](KerberosWorker::SetOnFinishedHandler onFinished) {
        auto client_state = std::make_shared<sspi_client_state>();
        client_state->channel_bindings_present = channel_bindings.supplied;
        client_state->channel_binding_data = channel_bindings.data;
        sspi_result result = auth_sspi_client_init(
            (WCHAR*)service.c_str(), gss_flags, (WCHAR*)user.c_str(), (ULONG)user.length(),
            (WCHAR*)domain.c_str(), (ULONG)domain.length(), (WCHAR*)password.c_str(), (ULONG)password.length(),
            (WCHAR*)mech_oid.c_str(), client_state.get());

        return onFinished([=](KerberosWorker* worker) {
            Napi::Env env = worker->Env();
            if (result.code == AUTH_GSS_ERROR) {
                worker->Call(std::initializer_list<napi_value>
                    { native_error(env, result), env.Null() });
                return;
            }

            worker->Call(std::initializer_list<napi_value>
                { env.Null(), KerberosClient::NewInstance(env, std::move(client_state)) });
        });
    });
}

void InitializeServer(const CallbackInfo& info) {
    throw Error::New(info.Env(), "`initializeServer` is not implemented yet for windows");
}

void PrincipalDetails(const CallbackInfo& info) {
    throw Error::New(info.Env(), "`principalDetails` is not implemented yet for windows");
}

void CheckPassword(const CallbackInfo& info) {
    throw Error::New(info.Env(), "`checkPassword` is not implemented yet for windows");
}

}
