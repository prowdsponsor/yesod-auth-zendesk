module Yesod.Auth.Zendesk
    ( YesodZendesk(..)
    , ZendeskUser(..)
    , Zendesk
    , getZendesk
    , redirectToZendesk
    ) where

#include "qq.h"
import Control.Monad.IO.Class (MonadIO, liftIO)
import Data.Default (Default(..))
import Data.Text (Text)
import Data.Time (getCurrentTime, formatTime)
import Language.Haskell.TH.Syntax (Pred(ClassP), Type(VarT), mkName)
import Yesod.Auth
import Yesod.Core
import qualified Data.Text as T


-- | Type class that you need to implement in order to support
-- Zendesk remote authentication.
--
-- /Minimal complete definition:/ all functions are required.
class YesodAuth master => YesodZendesk master where
  -- | Shared secret between Zendesk and your site.
  zendeskToken :: master -> Text

  -- | URL on your Zendesk's site where users should be
  -- redirected to when logging in.
  zendeskAuthURL :: master -> Text

  -- | Gather information that should be given to Zendesk about
  -- an user.  Please see 'ZendeskUser' for more information
  -- about what these fields mean.
  --
  -- Simple example:
  --
  -- @
  -- zendeskUserInfo = do
  --   Entity uid user <- 'requireAuth'
  --   return 'def' { 'zuName'  = userName user
  --                , 'zuEmail' = userEmail user }
  -- @
  --
  -- Advanced example:
  --
  -- @
  -- zendeskUserInfo = do
  --   uid <- 'requireAuthId'
  --   (user, org) <-
  --     runDB $ do
  --       Just user <- get uid
  --       Just org  <- get (userOrganization user)
  --       return (user, org)
  --   render <- 'getUrlRender'
  --   return 'def' { 'zuName'  = userName user
  --                , 'zuEmail' = userEmail user
  --                , 'zuOrganization' = Just (organizationName org)
  --                , 'zuRemotePhotoURL' = Just (render $ UserPhotoR uid)
  --                }
  -- @
  --
  -- /Note:/ although I don't recomend this and I don't see any
  -- reason why you would do it, it /is/ possible to use
  -- 'maybeAuth' instead of 'requireAuth' and login on Zendesk
  -- with some sort of guest user should the user not be logged
  -- in.
  zendeskUserInfo :: GHandler Zendesk master ZendeskUser


-- | Information about a user that is given to 'Zendesk'.  Please
-- see Zendesk's documentation
-- (<http://www.zendesk.com/support/api/remote-authentication>)
-- in order to see more details of how theses fields are
-- interpreted.
--
-- Only 'zuName' and 'zuEmail' are required.
data ZendeskUser =
  ZendeskUser
    { zuName :: Text
    -- ^ User name, at least two characters. (required)
    , zuEmail :: Text
    -- ^ E-mail address. (required)
    , zuExternalId :: ZendeskExternalId
    -- ^ An external (to Zendesk) ID that identifies this user.
    -- Defaults to 'UseYesodAuthId'.
    , zuOrganization :: Maybe Text
    -- ^ Organization the user belongs to.
    , zuTags :: [Text]
    -- ^ List of tags.
    , zuRemotePhotoURL :: Maybe Text
    -- ^ Public URL with the user's profile picture.
    } deriving (Eq, Ord, Show, Read)

-- | Fields 'zuName' and 'zuEmail' are required, so 'def' will be
-- 'undefined' for them.
instance Default ZendeskUser where
  def = ZendeskUser
          { zuName  = error "ZendeskUser's zuName is a required field."
          , zuEmail = error "ZendeskUser's zuEmail is a required field."
          , zuExternalId     = def
          , zuOrganization   = Nothing
          , zuTags           = []
          , zuRemotePhotoURL = Nothing
          }


-- | Which external ID should be given to Zendesk.
data ZendeskExternalId =
    UseYesodAuthId
    -- ^ Use the user ID from @persistent@\'s database.  This is
    -- the recommended and default value.
  | Explicit Text
    -- ^ Use this given value.
  | NoExternalId
    -- ^ Do not give an external ID.
    deriving (Eq, Ord, Show, Read)

-- | Default is 'UseYesodAuthId'.
instance Default ZendeskExternalId where
  def = UseYesodAuthId


----------------------------------------------------------------------


-- | Data type for @yesod-auth-zendesk@\'s subsite.
data Zendesk = Zendesk


-- | Create a new 'Zendesk', use this on your @config/routes@ file.
getZendesk :: a -> Zendesk
getZendesk = const Zendesk


mkYesodSub "Zendesk"
  [ClassP ''YesodZendesk [VarT $ mkName "master"]]
  [QQ(parseRoutes)|
  / ZendeskLoginR GET
|]


-- | Route used by Zendesk remote authentication.  We expect to
-- receive a timestamp from Zendesk.
getZendeskLoginR :: YesodZendesk master => GHandler Zendesk master ()
getZendeskLoginR = internalRedirectToZendesk . reqGetParams =<< getRequest


----------------------------------------------------------------------


-- | Redirect the user to Zendesk such that they're already
-- logged in when they arrive.  For example, you may use
-- @redirectToZendesk@ when the user clicks on a
redirectToZendesk :: YesodZendesk master => GHandler Zendesk master ()
redirectToZendesk = do
  now <- liftIO getCurrentTime
  let timestamp = T.pack $ formatTime locale "%s" now
      locale = error "redirectToZendesk: never here (locale not needed)"
  internalRedirectToZendesk [("timestamp", timestamp)]


-- | Internal function parametrized by the timestamp.
internalRedirectToZendesk :: YesodZendesk master =>
                             [(Text, Text)] -- ^ Request GET params.
                          -> GHandler Zendesk master ()
internalRedirectToZendesk params = do
  userInfo <- zendeskUserInfo
  undefined
