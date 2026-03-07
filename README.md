# boxit

Prevent Claude, Codex, and Gemini from messing up your laptop and Linux server by just running your CLI agent through boxit without constantly saying "yes" to let it do basic tasks:

```
boxit claude --dangerously-skip-permissions
```

By default, boxit will prevent:
- Changing files outside the current directory
- Making network requests outside of allowlisted domains and approved HTTP methods (GET)
- Pushing to git

### Customize your sandbox

To change what sites are reachable, you can modify the default boxit profile:

```
boxit profile custom-profile
cat ~/.boxit/custom-profile.json
{
    "allowedIps": ["10.0.0.1"],
    "allowedDomains": ["google.com"],
    "allowedPorts": ["tcp:22", "tcp:443]
}
```

```
boxit -p custom-profile claude
```

### Why not use Docker?

Docker is overkill. I want to run my agent on my laptop with all my installed tools and environment, but still have the full protections of a container. I do NOT want to have to recreate my environment with a Dockerfile for every project.

Docker isn't safe enough by default easily. Boxit gives you sane, safe defaults that let the AI do a lot, targetting AI agents instead of full application isolation like Kubernetes.

### How does it work?

Just like Docker/other container solutions, boxit uses Linux namespaces/MacOS sandboxes to create isolated environments. Instead of creating a fully isolated environment, however, boxit tries to keep the environment as close to the parent machine as possible to give a good experience. To prevent network access, boxit supports HTTP proxies and custom iptables rules to prevent excessive network access.