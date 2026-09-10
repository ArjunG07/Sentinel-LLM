import subprocess
import sys


def live_demo():
    from app.gateway import process_prompt

    print("\n========================================")
    print("          SENTINELLLM LIVE DEMO")
    print("========================================")
    print("\nSentinelLLM is protecting Qwen.")
    print("Type 'quit' to return to the main menu.\n")

    while True:
        query = input("You: ").strip()

        if query.lower() == "quit":
            break

        if not query:
            continue

        process_prompt(query)


def research_mode():
    print("\n========================================")
    print("       SENTINELLLM RESEARCH MODE")
    print("========================================")

    print("\n1. Run A/B/C Evaluation")
    print("2. Back to Main Menu")

    choice = input("\nSelect an option: ").strip()

    if choice == "1":
        print("\nStarting research evaluation...\n")

        subprocess.run(
            [sys.executable, "-m", "evaluation.runner"],
            check=False
        )

    elif choice == "2":
        return

    else:
        print("\nInvalid choice.")


def main():

    while True:

        print("\n========================================")
        print("              SENTINELLLM")
        print("       Adaptive Security Gateway")
        print("========================================")

        print("\n1. Live Demo")
        print("2. Research Evaluation")
        print("3. Exit")

        choice = input("\nSelect an option: ").strip()

        if choice == "1":
            live_demo()

        elif choice == "2":
            research_mode()

        elif choice == "3":
            print("\nSentinelLLM closed.")
            break

        else:
            print("\nInvalid choice. Please select 1, 2, or 3.")


if __name__ == "__main__":
    main()