add_subdirectory(SearchFile)
add_subdirectory(BingRequest)
add_subdirectory(BlackJack)
add_subdirectory(Oauth1Client)
add_subdirectory(Oauth2Client)
add_subdirectory(KiteApp)
add_subdirectory(Oauth2Kite)

add_custom_target(samples
  DEPENDS SearchFile BingRequest blackjackclient blackjackserver oauth1client oauth2client   oauth2kite
  )
