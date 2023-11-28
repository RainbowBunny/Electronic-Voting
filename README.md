The implementation based on this paper.
https://web.ua.es/es/recsi2014/documentos/papers/an-elliptic-curve-based-homomorphic-remote-voting-system.pdf

Todo: Change the hash function in utils, scale for more group of the voting systems.

- Create new user: 
```
user = User()
```
- To create a new server: 
```
voting_server = VotingServer(number_of_candidate = 4, maximum_number_of_voter = 300)
```
- To vote for a candidate, with candidate_id is a number between 0 and number_of_candidate - 1:
```
user_vote = user.vote(candidate_id, voting_server.get_public_key())
voting_server.cast_vote(user_vote)
```
- After the voting phase has finished, call:
```
voting_server.open_vote()
```
will return a list which is the number of votes for each candidate.