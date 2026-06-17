---
publishDate: 2025-06-17
draft: false
params:
  author: Joshua Wyss
title: Where KQL Failed me
weight: 10
keywords: thoughts
summary: If I could get the right query and the right automation in place, I could stop the problem before it started. Instead, both cases expose the same annoying truth, sometimes the data is the real blocker. Can I really blame the vendor though?
description: I’ve spent enough time writing detections to know that the hard part is rarely the query. In these two cases, I thought I had the right approach, but the missing data and delayed telemetry made the whole plan fall apart. It’s a reminder that sometimes the biggest limitation isn’t the tool, it’s the signal. Am I just Icarus trying to build something that isn't possible?
---
![[images/where_kql_failed_me.png]]

# Where KQL Failed me

I absolutely love log hunting! When I was told "Congratulations, in this post-merger company you are now in charge of the SIEM/SOAR work. Learn fast!" I was like, well logs sound terribly boring, but I like the idea of looking like a [movie computer hacker](https://hackertyper.net) staring at a wall of text. And, I loved listening to a past co-worker who enjoyed explaining his bespoke log ingestion/storage infrastructure to fresh-from-college-me. This could be fun right? (That attitude has served me well in so many mergers/acquisitions/role changes. Thanks mom & dad!)

Since getting started in Microsoft Sentinel there have only been 2 times that "KQL failed me". I knew going into both of these scenarios would be a challenge, but not impossible, but I also knew that it was a challenge worth taking on. Both of these scenarios, if successfully detected, would have been a measurable benefit to the environment I was tasked to secure. Unfortunately, both times it failed, not because KQL was a poor query language, but because of either an assumption I made at the star or a flaw in the data source.

## Trying to detect AI Meeting Transcription

It was specifically Read.AI that we were attempting to detect.

The company I worked at had a product/service that was sensitive in nature and during sales calls we did demos. The problem was that this was the beginning of everyone’s 'inviting' meeting recording AI tools to transcribe and summarize the conversation.

At that time, it was against the company's NDA to record or share, but the sales team (afraid to upset the potential customer) seemed unwilling to enforce that part of the agreement. So, I tried the detection route! I'd been successful at writing other custom detection so I hoped that this would be no different.

### The Goal

The goal was to alert when an external account joined a Teams meeting that matched a list of names that I compiled which matched common AI recording tools. Luckily today this isn't an issue, because Microsoft now has administrative controls to allow/block this.

After a meeting was detected, I would send the meeting ID to an Azure Logic app that would use a high permissioned service account to join a meeting then comment on the specific "leave the meeting" command for the AI tool. In the case of Read.AI any member of the meeting can send the chat message "Opt Out' which make "Read AI leave the meeting and deletes all measured data from that session. No report is generated." After typing the message, the service account would leave a brief message similar too "Meeting recordings are not allowed according to Acme Solutions' NDA and Acceptable Use Policies. Meeting recording ended." The Logic App would then send an email to the meeting organizer, CC their manager and the IT Security Director.

All of this was not meant to control or punish users, but to automate the enforcement of an obvious gap in customer relations and provide an opportunity for educating internal teams.

### The How

As of the time I’m writing this, I no longer have access to that environment, not to mention that it's been a few years, so I'll recount the details I can remember.

After reviewing logs, I was able to connect several log types and tables across Microsoft data sources. I started by monitoring the `OfficeActivity` table for Teams Meeting participants that had a DisplayName that I was looking for:

```kusto
OfficeActivity
| where OfficeWorkload == "MicrosoftTeams"
| where Operation == "CallParticipantDetail"
```

From there I matched one of the correlation IDs to another table that had a way to match a participant to a meeting ID. But from there is where the whole plan started to unravel.

The Meeting ID was great, but that particular log was missing the chat thread ID that would allow the service account to join the conversation without me having to add to the meeting (which could have been rejected by the organizer).

So, I had to wait until the first message was sent. This was okay for Read.AI and some others, because they would post a chat message upon joining. Once the first message was posted I could get the ChatThreadId and join and post the opt out message the chat session using the Microsoft Graph API action [Send chatMessage in a channel or a chat](https://learn.microsoft.com/en-us/graph/api/chatmessage-post?view=graph-rest-1.0&tabs=http).

AAAAAnd... It failed.

### Why did the query fail for participant detection?

In this case, all of the data points where available to me in the SIEM. Even more than that, they were all the data points I needed without having to infer anything or do string manipulation, or even correlate across vendors. It was perfect! Until it wasn't.

The scenario failed when I was trying to test in real life (was going to allow the Logic App to run but it was force terminated before joining the meeting.) The problem was that the log that showed external participants joining the meeting was delayed to the point of unitability. Sometimes I'd get the log 5 minutes after the agent joined the meeting, and one time I remember it was several hours after joining. While 5 minutes would be useful the average was longer than 30 minutes which made the success rate not worth pursuing.

Why not try and do it and catch the instances you could? In order to do this the Logic App required ChannelMessage.Send and Chat.ReadWrite.All which would have required a more solid use case to convince [the hands that hold the scepter](https://youtu.be/tDPMcdd7F0A?si=Lxn9jWin4LCLiHJd&t=34) to grant such high permission to a service account.

In the end it was a fun exercise for a newly minted SIEM engineer and I'm glad I was given the time to pursue it.

## Trying to detect Email Impersonation

Just like the previous scenario I had grand visions with this one. I could swoop in and solve a problem that had been plaguing the company for years. In this environment, for a long standing and valid reason, they had certain email security architecture that allowed some types of email impersonation to pass the 3rd party email security tool.

### The Problem

A significant uptick of SaaS impersonation campaigns were showing up and we were relying on users to report them (should we miss them ourselves through manual checks). In my mind any repeated manual check was prime real estate for automation!

So I got all excited that I really could do this and came up with this query:

```kusto
// Author:      Joshua Wyss
// Last Updated:2026-6-2
// Purpose:     Create alert when sender impersonating zoom has link to non-zoom domain. In early 2026 a rash of campaigns with zoom as sender and body as docusign linked to phishing domains. Email Security Tool couldn't catch b/c certain feature is disabled at this time and campaign load is unsustainable for users to continue manually reporting.
//
let commonGoodDomains = dynamic(["facebook.com","twitter.com","x.com","linkedin.com","instagram.com","google.com","youtube.com","yahoo.com","support.docusign.com"]); // ONLY ADD domains that are not abused for redirects (like monday.com or sendgrid.net etc)
EmailEvents
| where EmailDirection != "Outbound"
//| where SenderFromDomain has "zoom"
| where SenderFromAddress == "no-reply@zoom.us"
| join EmailUrlInfo on NetworkMessageId
//| summarize by EmailClusterId,Url,InternetMessageId,UrlDomain
| extend finalParsedTargetUrlOrDomain = parse_url(Url).["Query Parameters"].domain
| where not(finalParsedTargetUrlOrDomain has_any ("zoom.us","zoom.com")) and UrlDomain !has "zoom"
| extend ipcheck = ipv4_is_private(tostring(finalParsedTargetUrlOrDomain))
| where isempty(ipcheck) // Drop links that are IP Addresses (common for zoom to have IP addresses in emails)
//| extend finalParsedTargetUrlOrDomain = coalesce(finalParsedTargetUrlOrDomain,Url) // Url may not have been a the email security tool coded url, if so grab the naked url from Outlook
| where finalParsedTargetUrlOrDomain has "." // This removes when the "url" was a local file:/// reference
| where finalParsedTargetUrlOrDomain !endswith ".png" and finalParsedTargetUrlOrDomain !endswith ".jpg" and finalParsedTargetUrlOrDomain !endswith ".jpeg" and finalParsedTargetUrlOrDomain !endswith ".svg" and finalParsedTargetUrlOrDomain !endswith ".woff2" // Drop images
| where not(finalParsedTargetUrlOrDomain has_any (commonGoodDomains))
| join kind=leftouter (Ttp_Url_CL | where actions_s != "Block" | where url_s !startswith "file:") on $left.InternetMessageId==$right.messageId_s
| extend finalParsedTargetUrlOrDomain = coalesce(url_s,finalParsedTargetUrlOrDomain,Url) // Url may not have been a the email security tool coded url, if so grab the naked url from Outlook
// NOTE: EmailSecurityToolEncodedUrl = Any URL Email Security Tool sees gets encoded.
//                            B/c of this we can use this value as a unique identifier for campaign URLs regardless of it being clicked. :D
// NOTE: EmailSecurityToolDecodedUrl = ONLY URLs that were clikced by user gets a record in Ttp_Url_CL (where this value comes from). So Empty value means not yet clicked.
| extend EmailSecurityToolEncodedUrl = Url, EmailSecurityToolDecodedUrl = url_s
| project-keep TimeGenerated, finalParsedTargetUrlOrDomain, EmailSecurityToolEncodedUrl, EmailSecurityToolDecodedUrl, AuthenticationDetails, ConfidenceLevel, DetectionMethods, DeliveryLocation, EmailClusterId, EmailDirection, OrgLevelAction, OrgLevelPolicy, InternetMessageId, NetworkMessageId, RecipientEmailAddress, SenderFromAddress, SenderIPv4, SenderIPv6, SenderMailFromAddress, Subject, ThreatTypes, UrlCount, To, action_s, Category, tagMap_AdvancedPhishing_CredentialTheftBrands_s
```

Basically, it looks for domains that would be unexpected for a Zoom email. Why domains? It seemed the most reliable way to detect using logs.

Why not that thing?

- We could create a list of known subject lines, but that would require manual upkeep. Manual upkeep should always be avoided.
- Matching a string in the body might work, but the campaigns we cared about always impersonated Zoom, but the body was constantly changing.
- What about looking for a known good string in Zoom emails and alerting the rest? That would be too easy for an attacker to throw in a Zoom email footer.

But what they couldn't control was the zoom domain. While yes, Zoom emails do have other links to things like the sender's LinkedIn page or business Facebook group bad actors cannot control those either (Lets sidestep the redirect abuse conversation until later okay?) The only thing had to control here was where the link took the user.

### Why did query fail for email impersonatoin?

This particular Email Security Tool (EST for short) would rewrite links in the email body to allow us to block a domain/URL as well as track who visited it (hint hint). When I did my initial check into if we had the logs I saw that we got the logs for who sent the email, subject line, and the IMID. The IMID correlated the email to the table that held all of the rewritten links and their decoded destination.

I got excited that all of the pieces of the puzzle where there! Unfortunately, same as the previous scenario, it fell apart in testing.

The problem here stems from two places.

1. The EST's link rewriting only posted a log upon the first user click.
1. The encoded link was not only unique per destination but also unique per user. The encoding was just a single string of characters like `redirect.emailsecurity[.]me\asldfk9F2o90vZN0s9jfn438v9h2\domain=lol.gotcha[.]com`

Problem #1: Since we only got the decoded URL upon the first click, we couldn't _prevent_ everyone from clikcing. Since we couldn't block from arriving in the inbox, my original goal was to auto-block the links and auto-retract the emails.

Problem #2: My plan to enumerate all of the emails that needed retracted was to reverse lookup the IMID by the link in the email body. But this was not possible because the encoded link was unique per person + destination. There was no other way to identify emails across a campaign since they didn't even come from the same sending address or infrastructure (thanks Spam as a Service) See [Episode 110 of Darknet Diaries: Spam Botnets](https://darknetdiaries.com/episode/110/).

### The Outcome

Although this didn't work in the end it underscored the problem our security team was facing and how much effort we were putting into working around a problem created by a 10-year-old decision. This background gave 'ammo' to management in charge to push for a change to better email security overall.

### The redirect abuse conversation

Oh my, I'm not a vendor so I'm not sure how I'd protect against it, but there are several services I've seen that are being abused. linktracking.monday.com, sendgrid.com and MailerLite.com were all frequently used for redirecting using legitimate services.

It was somewhat common to have multiple redirect hops and now that I'm thinking of it, I wonder if our email security tool can protect against too many redirect hops? Note to self...

## Conclusion

With hundreds of gigabytes of text flowing to me, it can feel like running a SIEM is a kind of IT superpower. But the moments that stick with me are the ones where the data is delayed, incomplete, or just not able to be coorelated. In those cases, the problem is rarely that the query language is wrong but instead it’s that the signal isn’t available when it matters. And that’s what makes these failures so frustrating: the tools are powerful, but the world still has data gaps that no query can fully bridge.

What’s the one missing capability you’ve always wished a vendor would add?
