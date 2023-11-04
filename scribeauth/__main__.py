import argparse

from scribeauth import ScribeAuth

if __name__ == "__main__":
    parser = argparse.ArgumentParser("scribeauth")
    parser.add_argument("--client_id", help="Client ID provided by Scribe", type=str)
    parser.add_argument(
        "--user_pool_id", help="User pool ID provided by Scribe", type=str
    )
    parser.add_argument("--username", help="Username", type=str)
    parser.add_argument("--password", help="Password", type=str)
    args = parser.parse_args()
    auth = ScribeAuth({"client_id": args.client_id, "user_pool_id": args.user_pool_id})
    tokens = auth.get_tokens(username=args.username, password=args.password)
    print(tokens)
