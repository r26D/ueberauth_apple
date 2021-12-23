defmodule Ueberauth.Strategy.Apple do
  @moduledoc """
  Google Strategy for Überauth.
  """

  use Ueberauth.Strategy, uid_field: :uid, default_scope: "name email", ignores_csrf_attack: true

  alias Ueberauth.Auth.Info
  alias Ueberauth.Auth.Credentials
  alias Ueberauth.Auth.Extra
  alias Ueberauth.Failure.Error

  @state_param_cookie_name "apple.state.param"

  @doc """
  Handles initial request for Apple authentication.
  """
  def handle_request!(conn) do
    scopes = conn.params["scope"] || option(conn, :default_scope)
    response_type = conn.params["response_type"] || option(conn, :response_type)
    state = 24 |> :crypto.strong_rand_bytes() |> Base.url_encode64() |> binary_part(0, 24)

    params =
      [
        scope: scopes,
        response_type: response_type,
        response_mode: "form_post",
        state: state
      ]
      |> with_optional(:prompt, conn)
      |> with_optional(:access_type, conn)
      |> with_param(:access_type, conn)
      |> with_param(:prompt, conn)
      |> with_param(:response_mode, conn)

    opts = oauth_client_options_from_conn(conn)

    conn
    |> put_resp_cookie(@state_param_cookie_name, state)
    |> redirect!(Ueberauth.Strategy.Apple.OAuth.authorize_url!(params, opts))
  end

  @doc """
  Handles the callback from Apple.
  """
  def handle_callback!(%Plug.Conn{params: %{"code" => code} = params} = conn) do
    if state_param_matches?(conn) do
      user = (params["user"] && Ueberauth.json_library().decode!(params["user"])) || %{}
      opts = oauth_client_options_from_conn(conn)

      case Ueberauth.Strategy.Apple.OAuth.get_access_token([code: code], opts) do
        {:ok, token} ->
          %{"email" => user_email, "sub" => user_uid} =
            UeberauthApple.id_token_payload(token.other_params["id_token"])

          apple_user =
            user
            |> Map.put("uid", user_uid)
            |> Map.put("email", user_email)

          conn
          |> put_private(:apple_token, token)
          |> put_private(:apple_user, apple_user)

        {:error, {error_code, error_description}} ->
          set_errors!(conn, [error(error_code, error_description)])
      end
    else
      add_state_mismatch_error(conn, __MODULE__)
    end
  end

  @doc false
  def handle_callback!(%Plug.Conn{params: %{"error" => error}} = conn) do
    set_errors!(conn, [error("auth_failed", error)])
  end

  @doc false
  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No code received")])
  end

  @doc false
  def handle_cleanup!(conn) do
    conn
    |> put_private(:apple_user, nil)
    |> put_private(:apple_token, nil)
  end

  @doc """
  Fetches the uid field from the response.
  """
  def uid(conn) do
    uid_field =
      conn
      |> option(:uid_field)
      |> to_string

    conn.private.apple_user[uid_field]
  end

  @doc """
  Includes the credentials from the Apple response.
  """
  def credentials(conn) do
    token = conn.private.apple_token
    scope_string = token.other_params["scope"] || ""
    scopes = String.split(scope_string, ",")

    %Credentials{
      expires: !!token.expires_at,
      expires_at: token.expires_at,
      scopes: scopes,
      token_type: Map.get(token, :token_type),
      refresh_token: token.refresh_token,
      token: token.access_token
    }
  end

  @doc """
  Fetches the fields to populate the info section of the `Ueberauth.Auth` struct.
  """
  def info(conn) do
    user = conn.private.apple_user


    %Info{
      email: user["email"],
      name: get_name(user["name"]),
      first_name: get_first_name(user["name"]),
      last_name: get_last_name(user["name"])
    }
  end

  @doc """
  Stores the raw information (including the token) obtained from the google callback.
  """
  def extra(conn) do
    %Extra{
      raw_info: %{
        token: conn.private.apple_token,
        user: conn.private.apple_user
      }
    }
  end

  defp with_param(opts, key, conn) do
    if value = conn.params[to_string(key)], do: Keyword.put(opts, key, value), else: opts
  end

  defp with_optional(opts, key, conn) do
    if option(conn, key), do: Keyword.put(opts, key, option(conn, key)), else: opts
  end

  defp oauth_client_options_from_conn(conn) do
    request_options = conn.private[:ueberauth_request_options].options
    base_options = [redirect_uri: request_options[:callback_url] || callback_url(conn)]

    case {request_options[:client_id], request_options[:client_secret]} do
      {nil, _} -> base_options
      {_, nil} -> base_options
      {id, secret} -> [client_id: id, client_secret: secret] ++ base_options
    end
  end

  defp option(conn, key) do
    Keyword.get(options(conn), key, Keyword.get(default_options(), key))
  end

  defp add_state_mismatch_error(conn, _strategy) do
    conn
    |> set_errors!([
      %Error{message_key: :csrf_attack, message: "Cross-Site Request Forgery attack"}
    ])
    |> handle_cleanup!()
  end

  defp state_param_matches?(conn) do
    param_cookie = conn.params["state"]
    not is_nil(param_cookie) and param_cookie == get_state_cookie(conn)
  end

  defp get_state_cookie(conn) do
    conn
    |> Plug.Conn.fetch_session()
    |> Map.get(:cookies)
    |> Map.get(@state_param_cookie_name)
  end
  defp get_name(user) do
    [get_first_name(user), get_last_name(user)]
    |> Enum.reject(&is_nil/1)
    |> Enum.join(" ")
  end
  defp get_first_name(%{"firstName" => first_name}),do: first_name
  defp get_last_name(%{"lastName" => last_name}),do: last_name
end