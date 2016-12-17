"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _PKIStatusInfo = require("./PKIStatusInfo");

var _PKIStatusInfo2 = _interopRequireDefault(_PKIStatusInfo);

var _ContentInfo = require("./ContentInfo");

var _ContentInfo2 = _interopRequireDefault(_ContentInfo);

var _SignedData = require("./SignedData");

var _SignedData2 = _interopRequireDefault(_SignedData);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var TimeStampResp = function () {
	//**********************************************************************************
	/**
  * Constructor for TimeStampResp class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function TimeStampResp() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, TimeStampResp);

		//region Internal properties of the object
		/**
   * @type {PKIStatusInfo}
   * @description status
   */
		this.status = (0, _pvutils.getParametersValue)(parameters, "status", TimeStampResp.defaultValues("status"));

		if ("timeStampToken" in parameters)
			/**
    * @type {ContentInfo}
    * @description timeStampToken
    */
			this.timeStampToken = (0, _pvutils.getParametersValue)(parameters, "timeStampToken", TimeStampResp.defaultValues("timeStampToken"));
		//endregion

		//region If input argument array contains "schema" for this object
		if ("schema" in parameters) this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
  * Return default values for all class members
  * @param {string} memberName String name for a class member
  */


	_createClass(TimeStampResp, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, TimeStampResp.schema());

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for TSP_RESPONSE");
			//endregion

			//region Get internal properties from parsed schema
			this.status = new _PKIStatusInfo2.default({ schema: asn1.result["TimeStampResp.status"] });
			if ("TimeStampResp.timeStampToken" in asn1.result) this.timeStampToken = new _ContentInfo2.default({ schema: asn1.result["TimeStampResp.timeStampToken"] });
			//endregion
		}
		//**********************************************************************************
		/**
   * Convert current object to asn1js object and set correct values
   * @returns {Object} asn1js object
   */

	}, {
		key: "toSchema",
		value: function toSchema() {
			//region Create array for output sequence
			var outputArray = [];

			outputArray.push(this.status.toSchema());
			if ("timeStampToken" in this) outputArray.push(this.timeStampToken.toSchema());
			//endregion

			//region Construct and return new ASN.1 schema for this object
			return new asn1js.Sequence({
				value: outputArray
			});
			//endregion
		}
		//**********************************************************************************
		/**
   * Convertion for the class to JSON object
   * @returns {Object}
   */

	}, {
		key: "toJSON",
		value: function toJSON() {
			var _object = {
				status: this.status
			};

			if ("timeStampToken" in this) _object.timeStampToken = this.timeStampToken.toJSON();

			return _object;
		}
		//**********************************************************************************
		/**
   * Sign current TSP Response
   * @param {Object} privateKey Private key for "subjectPublicKeyInfo" structure
   * @param {string} [hashAlgorithm] Hashing algorithm. Default SHA-1
   * @returns {Promise}
   */

	}, {
		key: "sign",
		value: function sign(privateKey, hashAlgorithm) {
			//region Check that "timeStampToken" exists
			if ("timeStampToken" in this === false) return Promise.reject("timeStampToken is absent in TSP response");
			//endregion

			//region Check that "timeStampToken" has a right internal format
			if (this.timeStampToken.contentType !== "1.2.840.113549.1.7.2") // Must be a CMS signed data
				return Promise.reject("Wrong format of timeStampToken: " + this.timeStampToken.contentType);
			//endregion

			//region Sign internal signed data value
			var signed = new _ContentInfo2.default({ schema: this.timeStampToken.content });

			return signed.sign(privateKey, 0, hashAlgorithm);
			//endregion
		}
		//**********************************************************************************
		/**
   * Verify current TSP Response
   * @param {Object} verificationParameters Input parameters for verification
   * @returns {Promise}
   */

	}, {
		key: "verify",
		value: function verify() {
			var verificationParameters = arguments.length <= 0 || arguments[0] === undefined ? { signer: 0, trustedCerts: [], data: new ArrayBuffer(0) } : arguments[0];

			//region Check that "timeStampToken" exists
			if ("timeStampToken" in this === false) return Promise.reject("timeStampToken is absent in TSP response");
			//endregion

			//region Check that "timeStampToken" has a right internal format
			if (this.timeStampToken.contentType !== "1.2.840.113549.1.7.2") // Must be a CMS signed data
				return Promise.reject("Wrong format of timeStampToken: " + this.timeStampToken.contentType);
			//endregion

			//region Verify internal signed data value
			var signed = new _SignedData2.default({ schema: this.timeStampToken.content });

			return signed.verify(verificationParameters);
			//endregion
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "status":
					return new _PKIStatusInfo2.default();
				case "timeStampToken":
					return new _ContentInfo2.default();
				default:
					throw new Error("Invalid member name for TimeStampResp class: " + memberName);
			}
		}
		//**********************************************************************************
		/**
   * Compare values with default values for all class members
   * @param {string} memberName String name for a class member
   * @param {*} memberValue Value to compare with default value
   */

	}, {
		key: "compareWithDefault",
		value: function compareWithDefault(memberName, memberValue) {
			switch (memberName) {
				case "status":
					return _PKIStatusInfo2.default.compareWithDefault("status", memberValue.status) && "statusStrings" in memberValue === false && "failInfo" in memberValue === false;
				case "timeStampToken":
					return memberValue.contentType === "" && memberValue.content instanceof asn1js.Any;
				default:
					throw new Error("Invalid member name for TimeStampResp class: " + memberName);
			}
		}
		//**********************************************************************************
		/**
   * Return value of asn1js schema for current class
   * @param {Object} parameters Input parameters for the schema
   * @returns {Object} asn1js schema object
   */

	}, {
		key: "schema",
		value: function schema() {
			var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

			//TimeStampResp ::= SEQUENCE  {
			//    status                  PKIStatusInfo,
			//    timeStampToken          TimeStampToken     OPTIONAL  }

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [status]
    * @property {string} [timeStampToken]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "TimeStampResp",
				value: [_PKIStatusInfo2.default.schema(names.status || {
					names: {
						blockName: "TimeStampResp.status"
					}
				}), _ContentInfo2.default.schema(names.timeStampToken || {
					names: {
						blockName: "TimeStampResp.timeStampToken",
						optional: true
					}
				})]
			});
		}
	}]);

	return TimeStampResp;
}();
//**************************************************************************************


exports.default = TimeStampResp;
//# sourceMappingURL=TimeStampResp.js.map