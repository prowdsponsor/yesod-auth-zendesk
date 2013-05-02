module Yesod.Auth.Zendesk.Data
  ( Zendesk(..)
  , Route(ZendeskLoginR)
  , resourcesZendesk
  ) where

import Yesod.Core

-- | Data type for @yesod-auth-zendesk@\'s subsite.
data Zendesk = Zendesk

mkYesodSubData "Zendesk"
  [parseRoutes|
  / ZendeskLoginR GET
|]
